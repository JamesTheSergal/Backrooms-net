import socket
import threading
import time
from queue import Queue, Empty
from . import brAgentLog
from ..brNodeNet.brNode import brNode
from ..brNodeNet.brRoute import brRoute
from ..brSockets.brPacket import brPacket
from ..brNodeNet.controllerRequest import brControllerRequest
from ..brSockets.netconnection import netconnection
from ..brEnclave.Enclave import Enclave
from .brHandshake import brBasicHandshake

logger = brAgentLog

class brNetwork:
    
    def __init__(self, secureEnclave:Enclave, debug:bool=False):
        
        self.shutdown = False

        self.secureEnclave = secureEnclave
    
        # Threads
        self.listenerThreads:list[threading.Thread] = []
        self.initiatorThreads:list[threading.Thread] = []
        self.trafficThreads:list[threading.Thread] = []
        
        # Locks
        self.controllerLock = threading.Lock()
        
        # Tracking
        self.trackedConnections:list[netconnection] = [] # Key is IP address
        
        # Stats
        self.statsLock = threading.Lock()
        self.handledIncomingBytes = 0
        self.handledOutgoingBytes = 0
        self.respondedToRequests = 0
        # ------------
        
        # For external controller
        self.toRouter = Queue(maxsize=25000)
        self.connectRequest = Queue(maxsize=25000)
        
    def startListener(self, bindAddress:str="127.0.0.1", nodePort:int=13337):
        logger.info(f"Starting node connection listener on: {bindAddress}:{nodePort}")
        newSpawn = threading.Thread(name="brNodeNetworkListener", target=self.connectionListener, args=[bindAddress, nodePort])
        self.listenerThreads.append(newSpawn)
        newSpawn.start()
    
    def startInitiator(self, bindAddress:str="127.0.0.1"):
        logger.info(f"Starting node connection initiator on {bindAddress}")
        newSpawn = threading.Thread(name="brNodeNetworkInitiator", target=self.connectionInitiator, args=[])
        self.initiatorThreads.append(newSpawn)
        newSpawn.start()
    
    def connectionListener(self, bindAddress:str, nodePort:int):
        
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((bindAddress, nodePort))
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
                
                pendingNode = brNode(ip, port)

                pendingRoute = brRoute(routeType=brRoute.brRouteType.TEST,
                                       assignedConn=trackconnection,
                                       externalNode=pendingNode, 
                                       connectionType=brRoute.brConnectionDirection.RECEIVED
                )
                self.secureEnclave.appendOntoList("nodeRoutes", pendingRoute)

                spawnThread = threading.Thread(name=f'brNodeCon-received-({address})',target=self.__connectionThread__, args=[pendingRoute])
                self.trafficThreads.append(spawnThread)
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
                connectjob:brRoute = self.connectRequest.get(block=True, timeout=0.15)
            except Empty:
                # This is to be expected a lot
                connectjob = None

            if connectjob is not None:
                
                outboundIP = connectjob.externalNode.nodeIP
                outboundPort = connectjob.externalNode.nodePort

                try:
                    obsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    logger.debug("Attempting to connect to node...")
                    obsoc.connect((outboundIP, outboundPort))
                    
                    connectjob.assignedConn = netconnection(soc=obsoc,
                                                            ip=outboundIP,
                                                            port=outboundPort,
                                                            connected=True,
                                                            encryptionident=self.secureEnclave.assignedIdentity
                    )
                    
                    spawnThread = threading.Thread(name=f'brNodeCon-outbound-({outboundIP})',target=self.__connectionThread__, args=[connectjob])
                    self.trafficThreads.append(spawnThread)
                    spawnThread.start()
                    logger.debug("Connected.")
                except ConnectionRefusedError:
                    # Action to be taken about failure
                    logger.exception("Cannot connect to node! Connection refused!", exc_info=False)
                except:
                    # Fill this in later
                    logger.exception("Connection error!", exc_info=True)
            else:
                time.sleep(0.15)
    
        # Broke out of loop. We must be shutting down.
        logger.info("Node connection initiator received shutdown, refusing new connections.")
        #logger.info(f'Waiting for {len(self.outboundNodeThreads)} threads to shutdown...')

        #while len(self.outboundNodeThreads) > 0:
        #    logger.info(f'Waiting for {len(self.outboundNodeThreads)} threads to shutdown...')
        #    for thr in self.outboundNodeThreads:
        #        thr.join(timeout=5.0)
        #        if not thr.is_alive():
        #            logger.info(f'Thread {thr.native_id} shutdown...')
        #            self.outboundNodeThreads.remove(thr)
                
        #logger.info("All threads closed. Exiting main loop.")
                
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
    
    