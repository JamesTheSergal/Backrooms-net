import socket
import threading
import time
from queue import Queue, Empty
from . import brAgentLog
from ..brNodeNet.brNode import brNode
from ..brNodeNet.brRoute import brRoute
from ..brSockets.brPacket import brPacket
from ..brSockets.netconnection import netconnection
from ..brEnclave.Enclave import Enclave
from ..brNodeNet.events import NetworkEvent, EventType
from .brHandshake import brBasicHandshake

logger = brAgentLog

class ConnectionManager:
    
    def __init__(self, secureEnclave:Enclave, event_queue:Queue):
        
        self.shutdown = False
        self.secureEnclave = secureEnclave
        self.event_queue = event_queue
        self.connect_request_queue = Queue(maxsize=1000)
        self.trackedConnections = []
    
  
        self.listenerThreads = []
        self.initiatorThreads = []
        self.io_threads = []
        
        
    def startListener(self, bind_address, port):
        newSpawn = threading.Thread(name="brNodeNetworkListener", target=self.connectionListener, args=[bind_address, port])
        self.listenerThreads.append(newSpawn)
        newSpawn.start()
    
    def startInitiator(self):
        newSpawn = threading.Thread(name="brNodeNetworkInitiator", target=self.connectionInitiator, args=[])
        self.initiatorThreads.append(newSpawn)
        newSpawn.start()
    
    def connectionListener(self, bind_address, port):
        
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((bind_address, port))
            soc.listen(4)
            soc.settimeout(0.5)

        except Exception as e:
            logger.exception("Error occured when creating socket!", exc_info=True)
            return
        
        while self.shutdown is False:

            # Handle incoming first
            try:
                connection, address = soc.accept()

                # Check to see if we have seen this connection before
                ip = address[0]
                port = address[1]

                trackconnection = netconnection(connection, ip, port, True, encryptionident=self.secureEnclave.assignedIdentity)
                self.trackedConnections.append(trackconnection)
                
                pendingNode = brNode(ip, port, connected=True)

                pendingRoute = brRoute(routeType=brRoute.brRouteType.TEST,
                                       assignedConn=trackconnection,
                                       externalNode=pendingNode, 
                                       connectionType=brRoute.brConnectionDirection.RECEIVED
                )
                self.event_queue.put(NetworkEvent(
                    EventType.CONNECTION_ESTABLISHED,
                    route=pendingRoute
                    ))

                spawnThread = threading.Thread(name=f'brNodeCon-received-({ip})',target=self._connection_io_loop, args=[pendingRoute])
                self.io_threads.append(spawnThread)
                spawnThread.start()
            except TimeoutError:
                # This is normal. It gives us time to loop and check threads.
                pass
                #deadThreads = []
                #for thr in self.inboundNodeThreads:
                #    if not thr.is_alive():
                #        deadThreads.append(thr)
                #
                #for thr in deadThreads:
                #    self.inboundNodeThreads.remove(thr)
            
        
        # Broke out of loop. We must be shutting down.
        logger.info("Node connection listener received shutdown, refusing new connections.")
        #logger.info(f'Waiting for {len(self.inboundNodeThreads)} threads to shutdown...')

        #while len(self.inboundNodeThreads) > 0:
        #    logger.info(f'Waiting for {len(self.inboundNodeThreads)} threads to shutdown...')
        #    for thr in self.inboundNodeThreads:
        #        thr.join(timeout=5.0)
        #        if not thr.is_alive():
        #            logger.info(f'Thread {thr.native_id} shutdown...')
        #            self.inboundNodeThreads.remove(thr)
                
        #logger.info("All threads closed. Exiting main loop.")
        
    def connectionInitiator(self):

        while self.shutdown is False:

            try:
                # Get a route that we should try to connect to
                route: brRoute = self.connect_request_queue.get(timeout=0.3)
            except Empty:
                continue

            if route is None:
                continue

            self._attempt_outbound_connection(route)

        logger.info("Connection Initiator shutting down.")

    def request_connection(self, route: brRoute):
        """Public API for the controller to request an outbound connection."""
        if route.connectionType != brRoute.brConnectionDirection.INITIATED:
            logger.error("Cannot request connection on a RECEIVED route")
            return
        self.connect_request_queue.put(route)

    def _attempt_outbound_connection(self, route: brRoute):
        """Actually performs the socket connection and sets up the I/O thread."""
        ip = route.externalNode.nodeIP
        port = route.externalNode.nodePort
        
        try:
            logger.debug(f"Initiating outbound connection to {ip}:{port}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            
            route.assignedConn = netconnection(
                soc=sock,
                ip=ip,
                port=port,
                connected=True,
                encryptionident=self.secureEnclave.assignedIdentity
            )
            
            self.trackedConnections.append(route.assignedConn)
            
            # Start the thin I/O thread (same one used by listener)
            io_thread = threading.Thread(
                name=f"brNodeCon-outbound-{ip}",
                target=self._connection_io_loop,
                args=[route],
                daemon=True
            )
            self.io_threads.append(io_thread)
            io_thread.start()
            
            # Notify the controller that the connection was established
            self.event_queue.put(NetworkEvent(
                event_type=EventType.CONNECTION_ESTABLISHED,
                route=route
            ))
            
            logger.info(f"Successfully connected to {ip}:{port}")
            
        except ConnectionRefusedError:
            logger.warning(f"Connection refused by {ip}:{port}")
            self.event_queue.put(NetworkEvent(
                event_type=EventType.CONNECTION_CLOSED,
                route=route,
                error=ConnectionRefusedError("Connection refused")
            ))
        except Exception as e:
            logger.exception(f"Failed to connect to {ip}:{port}")
            self.event_queue.put(NetworkEvent(
                event_type=EventType.CONNECTION_CLOSED,
                route=route,
                error=e
            ))

    def _connection_io_loop(self, route: brRoute):
        """Thin I/O thread. Only reads, writes, and posts events."""
        conn = route.assignedConn
        logger.info(f"IO thread for route {route.routeID} opened")
        
        while not self.shutdown and route.externalNode.connected:
            try:
                if route.encryptionUpgraded:
                    packet = conn.receivePacketRaw()
                    packet = self.secureEnclave.assignedIdentity.decryptChunk(packet)
                    packet = brPacket(packet)
                else:
                    packet = conn.receivePacket()
                if packet:
                    self.event_queue.put(NetworkEvent(
                        EventType.PACKET_RECEIVED, 
                        route=route, 
                        packet=packet
                    ))
            except Empty:
                pass
            except socket.timeout:
                pass
            except Exception as e:
                self.event_queue.put(NetworkEvent(
                    EventType.CONNECTION_CLOSED, 
                    route=route, 
                    error=e
                ))
                break

            # Send anything in the outbox (non-blocking)
            while not route.outbox.empty():
                try:
                    data = route.outbox.get_nowait()
                    if route.encryptionUpgraded:
                        data = route.externalNode.identity.chunkEncrypt(data)
                        conn.send(data[0])
                    else:
                        conn.send(data)
                except:
                    self.event_queue.put(NetworkEvent(
                    EventType.CONNECTION_CLOSED, 
                    route=route, 
                    error=e
                    ))
                    break
        logger.info(f"IO thread for route {route.routeID} closed")
            
    def wait_until_outbox_clear(self, route: brRoute):
        while not route.outbox.empty():
            time.sleep(0.25)
    
    def __connectionThread__(self, nodeRoute:brRoute):

        if nodeRoute.connectionType is brRoute.brConnectionDirection.INITIATED:
            nodeConfig = {"uuid": self.secureEnclave.returnData("selfUUID"), "webport":self.secureEnclave.returnData("webPort"), "dhtPort":self.secureEnclave.returnData("dhtPort")}
            brBasicHandshake(nodeRoute.assignedConn).initiate(nodeConfig) # TODO: add connectionreseterror exception
            nodeRoute.externalPubKeyCheck()
            self.toRouter.put(brControllerRequest(brControllerRequest.requestType.SUBMIT_KNOWN_NODE, nodeRoute.externalNode))
        else:
            nodeConfig = brBasicHandshake(nodeRoute.assignedConn).receive()
            nodeRoute.externalNode.setNodeUUID(nodeConfig["uuid"])
            nodeRoute.externalNode.webPort = nodeConfig["webport"]
            nodeRoute.externalNode.dhtport = nodeConfig["dhtPort"]
            nodeRoute.externalPubKeyCheck()
            self.toRouter.put(brControllerRequest(brControllerRequest.requestType.SUBMIT_KNOWN_NODE, nodeRoute.externalNode))
        
        # START OF CONTINUOUS LOOP
        #
        #
        #
        
        nodeRoute.setConnectedState(True)
        con = nodeRoute.assignedConn
        
        while not self.shutdown:

            # Receive action
            try:
                packet = con.receivePacket()
            except:
                logger.exception("Critical error when receiving data!", exc_info=True)
                break

            
            # Decision making / Send to Controller for more data
            
            # Decision table
            connected = nodeRoute.externalNode.connected
            fullHandshake = nodeRoute.externalNode.finishedHandshake
  
            # if conditions are met, send to router 
            
            match packet.messageType:
                
                case brPacket.brMessageType.CALLBACK_PING:
                    # We are currently IDLE
                    nodeRoute.setRouteStateIdle()
                    time.sleep(1)
                    con.sendPing()
                    with self.statsLock:
                        self.respondedToRequests += con.requeststatupdate()
                        self.handledIncomingBytes += con.instatupdate()
                        self.handledOutgoingBytes += con.outstatupdate()
            
            
            #if reply == False:
            #    logger.error("Got a false return from the router. Something went wrong. Exiting.")
            #    connection.close()
            #    break
            #elif reply == True:
            #    nodeRoute.setRouteStateIdle()
            #    # We have time to look for messages and news
            #    
            #    
            #    packet = brPacket().createCallbackPing()
            #    reply = nodeRoute.thirdParty.identity.chunkEncrypt(packet)[0]
            #    time.sleep(0.5)
            #else:
            #    nodeRoute.setRouteStateBusy()
            #    if nodeRoute.encryptionUpgraded:
            #        reply = nodeRoute.thirdParty.identity.chunkEncrypt(reply)[0]
            #    
            #    # Last step of the handshake process. Makes sure that the packet goes out without being encrypted
            #    if nodeRoute.thirdParty.finishedHandshake == True and nodeRoute.encryptionUpgraded == False:
            #        with nodeRoute.routeThreadLock:
            #            nodeRoute.encryptionUpgraded = True

            #ourOutgoingBytes += len(reply)
            #connection.sendall(reply)
                
            # If our route was Idle, send our stats really quick
            #if nodeRoute.routeState == "Idle":
            #    with self.statsLock:
            #        self.handledIncomingBytes += ourHandledBytes
            #        self.handledOutgoingBytes += ourOutgoingBytes
            #        self.respondedToRequests += ourHandledRequests
            #        ourHandledBytes = 0
            #        ourOutgoingBytes = 0
            #        ourHandledRequests = 0
            

        
        # We broke out, find out why!
        if self.shutdown:
            logger.info("Thread got shutdown signal.")
            nodeRoute.setConnectedState(False)
            con.close()
        else:
            logger.info(f'Thread abnormal shutdown.')
            #nodeRoute.setConnectedState(False)
            con.close()

        
        # Publish our stats really quick
        #with self.statsLock:
        #    self.handledIncomingBytes += ourHandledBytes
        #    self.handledOutgoingBytes += ourOutgoingBytes
        #    self.respondedToRequests += ourHandledRequests
    
    