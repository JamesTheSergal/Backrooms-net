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
from .brHandshake import brHandshake, brControllerRequest

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
                
                pendingNode = brNode()
                pendingNode.setNodeAddress(address)

                pendingRoute = brRoute(brRoute.brRouteType.TEST, connection, pendingNode, brRoute.brConnectionDirection.RECEIVED)

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
                    connectjob.assignedConn = obsoc
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
    
    def __handshakeSafeLoop__(self, nodeRoute:brRoute):
        
        
        netAddress = nodeRoute.externalNode.nodeIP
        netPort = nodeRoute.externalNode.nodePort
        connection = nodeRoute.assignedConn
        
        # Check if we are the initiator and send introduction packet
        if nodeRoute.connectionType is brRoute.brConnectionDirection.INITIATED:
            sequence:Queue = brHandshake.brInitiateBasicHandshake()
            runnable = sequence.get()
            message = runnable()
            try:
                connection.sendall(message)
                logger.info(f"Sent introduction packet to {netAddress}")
            except:
                logger.exception("We attempted to initiate the connection and failed to get a proper response!", exc_info=True)
        else:
            sequence:Queue = brHandshake.brReceiveBasicHandshake()
            
        while nodeRoute.externalNode.finishedUnencryptedHandshake is False:
            
            # Receive action
            try:
                rawpacket = connection.recv(1500)  # TODO: Set time-out to kill threads we aren't using
                #ourHandledBytes += len(rawpacket)
                message = brPacket(rawpacket)
                nodeRoute.mostRecentPacket = message

            except:
                logger.exception("Critical error when receiving data!", exc_info=True)
                break
            
            runnable = sequence.get()
            result = runnable(message)
            
            if type(result) is brHandshake.handshakeResult:
                result:brHandshake.handshakeResult
                if result.error is False:
                    runnable = sequence.get()
                    result = runnable()
                    if type(result) is bytes:
                        connection.send(result)
                    elif type(result) is brControllerRequest:
                        result:brControllerRequest
                        result.routeInfo = nodeRoute
                        self.toRouter.put(result)
                        logger.info("Waiting for controller request to complete...")
                        result.waitForRequestComplete()
                        logger.info("Request completed")
                        connection.sendall(result.response)
                else:
                    logger.error(f'Error with handshake validation: {result.additionalInfo} {result.rawData}')
                    connection.close()
                    break
            elif type(result) is brControllerRequest:
                result:brControllerRequest
                result.routeInfo = nodeRoute
                self.toRouter.put(result)
                logger.info("Waiting for controller request to complete...")
                result.waitForRequestComplete()
                logger.info("Request completed")
                connection.sendall(result.response)
            elif type(result) is bytes:
                pass
        
        logger.info("Completed basic handshake!")
       
    
    def __connectionThread__(self, nodeRoute:brRoute):

        netAddress = nodeRoute.externalNode.nodeIP
        netPort = nodeRoute.externalNode.nodePort
        connection = nodeRoute.assignedConn
        

        # Statistics gathering
        ourHandledBytes = 0
        ourOutgoingBytes = 0
        ourHandledRequests = 0
        # ----

        self.__handshakeSafeLoop__(nodeRoute=nodeRoute)
        
        # START OF CONTINUOUS LOOP
        #
        #
        #
        
        nodeRoute.setConnectedState(True)
        
        while not self.shutdown:

            # Receive action
            try:
                rawpacket = connection.recv(1500)  # TODO: Set time-out to kill threads we aren't using
                ourHandledBytes += len(rawpacket)
            except:
                logger.exception("Critical error when receiving data!", exc_info=True)
                break
            
            # Decrypt and parse
            try:
                if rawpacket:
                    if nodeRoute.encryptionUpgraded:
                        rawpacket = self.secureEnclave.assignedIdentity.decryptChunk(rawpacket)
                        #TODO: Out of sync encryption when reconnecting to node.
                        #Must find a better way to coordinate 
                    message = brPacket(rawpacket)
                    nodeRoute.mostRecentPacket = message
                else:
                    logger.info("Got empty packet. This thread will close.")
                    connection.close()
                    break
            except Exception as e:
                logger.exception("Critical error when processing client packet!", exc_info=True)
                break
            
            # Decision making / Send to Controller for more data
            
            # Decision table
            connected = nodeRoute.externalNode.connected
            basicHandshake = nodeRoute.externalNode.finishedUnencryptedHandshake
            fullHandshake = nodeRoute.externalNode.finishedHandshake
  
            # if conditions are met, send to router 
            

            if message.messageType is brPacket.brMessageType.INTRODUCE or brPacket.brMessageType.READY:
                try:
                    self.toRouter.put(nodeRoute)
                    ourHandledRequests+= 1
                except Exception as e:
                    logger.exception("Critical error when processing request!", exc_info=True) # TODO: handle brInvalidMessageType
                    break
                
                logger.info("Waiting for router to process packet...")
                while not nodeRoute.routerActionConfirmation():
                    time.sleep(1)
                logger.info("Router has responded to the packet!")
            
            # Decisions that can be made without the router/controller
            
            if not connected:
                logger.error("Node disconnect after router processing")
                connection.close()
                break
            
            # Process route inbox and outbox
            
            try:
                job = nodeRoute.outbox.get(block=True, timeout=0.15)
            except Empty:
                pass
            if type(job) is bytes:
                connection.sendall(job)
            else:
                logger.error("Unknown job type received from Router.")
            
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
            connection.close()
        else:
            logger.info(f'Thread abnormal shutdown.')
            #nodeRoute.setConnectedState(False)
            connection.close()

        
        # Publish our stats really quick
        #with self.statsLock:
        #    self.handledIncomingBytes += ourHandledBytes
        #    self.handledOutgoingBytes += ourOutgoingBytes
        #    self.respondedToRequests += ourHandledRequests
    
    