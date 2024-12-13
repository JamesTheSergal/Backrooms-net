from enum import IntEnum
import logging
from pathlib import Path
import pprint
import random
import socket
import os
import threading
import time
import uuid
import requests
from core import loggingfactory, notrustvars
from core.brNodeNetworkUtil import brNodeManager
from core.brDataBuilder import brPacket
#from node import BR_VERSION

from . import BR_VERSION

# Backrooms-net route types and levels

# Control Route - Used internally to consistently talk with other nodes to discuss security, opening routes, ect...
# Test Route - Used internally to test the viability of a route.
# Unencrypted - Can be used if the client on the other end handles it's own encryption/doesn't need it.
#   (Levels) None, Hops(1-12)
# Encrypted - Encrypted with each Node's RSA key. (Onion)
#   (Levels) No-Onion, Hops(1)
#            Low, Hops(2-3), 
#            Medium, Hops(4-5),
#            High, Hops(6-12)
# Highway - If there are many connections going out to one client on the network, a highway (Still a route) can be created.
#           By using a highway, which is a single connection, we can bunch up users together to blend their traffic.
#           This hardens against timing attacks.
#
#           When to use? - When we have more than 5 clients going to the same place.
#           Completely optional. It is up to the client to decide if they want to join the highway.
#           A highway will use the most common level 

#
# On the network
#
#               (No Identification)
# Client A (UUID4) --- HOPS --- Client B (UUID4)

# Backrooms message types and explations
#
# 1. Challenge - We have received the public key of the connecting party
# We will give them a random number to decrypt (16 Bytes)
#
# 2. Challenge response - We just send the number back using the originators public key
#
# 3. Ask For Friends - Simply ask for friends
#
# 4. Friend announce - One friend per message
#
# 5. Connection Test - Blank secure message to test latency
#
# 6. Message from client



logger = loggingfactory.createNewLogger("brNodeNetwork")

class brNodeServer:

    class brNodeServerException(Exception):
        """Exception base class for the brWebServer."""
        pass

    def __init__(self, secureEnclave:notrustvars.enclave, bindAddress:str="127.0.0.1", nodePort:int=443, insecurePort:int=80, debug=False) -> None:
                
        # If debug is set, we will log at the lowest level + debug timings
        self.debug = debug
        # ------------

        # Network setup
        self.bindAddress = bindAddress
        self.nodePort:int = nodePort
        self.insecurePort:int = insecurePort
        # ------------

        # Secure Enclave for peer stats
        self.secureEnclave = secureEnclave
        # ------------
        
        # Create enclave values if they aren't existing already
        self.secureEnclave.createIfNotExist("knownNodes", dict())
        # ------------

        # managers
        self.nodeManager = brNodeManager(self.secureEnclave)

        # Network controller specific
        self.controllerLock = threading.Lock()
        self.ourClients = {}
        self.knownClients = {}
        self.knownNodes:dict[str][brNodeRecord] = secureEnclave.returnData("knownNodes")
        self.globalAnnounce:list = []
        # Controller Notes
        # Keys in Enclave:
        # knownNodes
        # ------------

        # Threads
        self.thrLock = threading.Lock()
        self.controllerThread:threading.Thread = None
        self.inboundThread:threading.Thread = None
        self.outboundThread:threading.Thread = None
        self.inboundNodeThreads:list[threading.Thread] = []
        self.outboundNodeThreads:list[threading.Thread] = []
        # ------------

        # Server state flags
        self.running = False
        self.shutdown = False
        # ------------

        # Stats
        self.statsLock = threading.Lock()
        self.handledIncomingBytes = 0
        self.handledOutgoingBytes = 0
        self.respondedToRequests = 0
        # ------------

    def startServer(self):
        logger.info("Started node server.")
        if not self.running:
            self.controllerThread = threading.Thread(name="brNetworkController", target=self.__networkController__, args=[])
            self.inboundThread = threading.Thread(name="brNodeNetworkInbound", target=self.__inboundLoop__, args=[])
            self.outboundThread = threading.Thread(name="brNodeNetworkOutbound", target=self.__outboundLoop__, args=[])
            self.controllerThread.start()
            self.inboundThread.start()
            self.outboundThread.start()

    def shutdownServer(self):
        self.shutdown = True
        logger.info("Sent shutdown signal - Node Main Thread is now waiting...")
        self.inboundThread.join()
        self.outboundThread.join()
        self.controllerThread.join()

    def __inboundLoop__(self):
        
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((self.bindAddress, self.nodePort))
            soc.listen(4)
            soc.settimeout(0.5)
            self.running = True
        except Exception as e:
            logger.exception("Error occured when creating socket!", exc_info=True)
            self.running = False
            return
        
        while self.shutdown is False:

            # Handle incoming first
            try:
                connection, address = soc.accept()

                # Check to see if we have seen this connection before
                nodeIP = address[0]

                if nodeIP in self.knownNodes.keys():
                    pendingNode = self.knownNodes[nodeIP]
                else:
                    pendingNode = brNodeRecord()
                    pendingNode.setNodeAddress(address)
                    with self.controllerLock:
                        self.knownNodes[nodeIP] = pendingNode
                    

                pendingRoute = brRoute(brRoute.brRouteType.TEST, connection, pendingNode)

                spawnThread = threading.Thread(name=f'brNodeCon-inbound-({address})',target=self.__connectionThread__, args=[pendingRoute, "inbound"])
                self.inboundNodeThreads.append(spawnThread)
                self.inTesting.append(pendingRoute)
                spawnThread.start()
            except socket.timeout:
                # This is normal. It gives us time to loop and check threads.

                deadThreads = []
                for thr in self.inboundNodeThreads:
                    if not thr.is_alive():
                        deadThreads.append(thr)

                for thr in deadThreads:
                    self.inboundNodeThreads.remove(thr)
            
        
        # Broke out of loop. We must be shutting down.
        logger.info("Inbound Node loop received shutdown, refusing new connections.")
        logger.info(f'Waiting for {len(self.inboundNodeThreads)} threads to shutdown...')

        while len(self.inboundNodeThreads) > 0:
            logger.info(f'Waiting for {len(self.inboundNodeThreads)} threads to shutdown...')
            for thr in self.inboundNodeThreads:
                thr.join(timeout=5.0)
                if not thr.is_alive():
                    logger.info(f'Thread {thr.native_id} shutdown...')
                    self.inboundNodeThreads.remove(thr)
                
        logger.info("All threads closed. Exiting main loop.")

    def __outboundLoop__(self):

        while self.shutdown is False:

            if len(self.pendingConnect) > 0:

                with self.connPoolLock:
                    outboundConnect = self.pendingConnect.pop()
                
                outboundIP = outboundConnect.thirdParty.nodeIP
                outboundPort = outboundConnect.thirdParty.nodePort

                try:
                    obsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    logger.debug("Attempting to connect to node...")
                    obsoc.connect((outboundIP, outboundPort))
                    outboundConnect.assignedConn = obsoc
                    spawnThread = threading.Thread(name=f'brNodeCon-outbound-({outboundIP})',target=self.__connectionThread__, args=[outboundConnect, "outbound"])
                    self.outboundNodeThreads.append(spawnThread)
                    spawnThread.start()
                    logger.debug("Connected.")
                except ConnectionRefusedError:
                    with self.thrLock:
                        self.failedToConnect.append(outboundConnect)
                    logger.exception("Cannot connect to node! Connection refused!", exc_info=False)
                except:
                    with self.thrLock:
                        self.failedToConnect.append(outboundConnect)
                    logger.exception("Connection error!", exc_info=True)
            else:

                # Dead thread sweep
                deadThreads = []
                for thr in self.outboundNodeThreads:
                    if not thr.is_alive():
                        deadThreads.append(thr)

                for thr in deadThreads:
                    self.outboundNodeThreads.remove(thr)


                time.sleep(0.1)
        
        # Broke out of loop. We must be shutting down.
        logger.info("Outbound Node loop received shutdown, refusing new connections.")
        logger.info(f'Waiting for {len(self.outboundNodeThreads)} threads to shutdown...')

        while len(self.outboundNodeThreads) > 0:
            logger.info(f'Waiting for {len(self.outboundNodeThreads)} threads to shutdown...')
            for thr in self.outboundNodeThreads:
                thr.join(timeout=5.0)
                if not thr.is_alive():
                    logger.info(f'Thread {thr.native_id} shutdown...')
                    self.outboundNodeThreads.remove(thr)
                
        logger.info("All threads closed. Exiting main loop.")
            
    def __debugToFile__(data: bytes, id, count):
        tempdir = Path(f'temp/{id}')
        if not tempdir.is_dir():
            os.mkdir(f'temp/{id}')
        with open(f'temp/{id}/{str(count)}.packet', 'ab') as df:
            df.write(data)
        logger.debug(f'Wrote packet to: temp/{id}/{str(count)}.packet')

    def __router__(self, packet: brPacket, nodeRoute:brRoute, mode:str):
        if packet.messageType == brPacket.brMessageType.INTRODUCE:

            if mode == "inbound":
                # By default in inbound mode we will only get the connection port. (Randomly assigned internet port)
                # If we want to reconnect, the introduction packet will have the ports configured on the other side.
                thirdpartyconfig = packet.data.decode('utf-8')
                configSplit = thirdpartyconfig.split('-')
                thirdPartyWebPort = int(configSplit[0])
                thirdPartyNodePort = int(configSplit[1])

                nodeRoute.thirdParty.webPort = thirdPartyWebPort
                nodeRoute.thirdParty.nodePort = thirdPartyNodePort
                
            if not nodeRoute.thirdPartyPubKeyCheck():
                logger.error("Could not get public key from node to establish identity!")
                return False
                
            chunks = nodeRoute.thirdParty.identity.chunkEncrypt(str(nodeRoute.routeSecret).encode('utf-8')) # Should just be one chunk
            reply = brPacket()
            reply.setMessageType(brPacket.brMessageType.CHALLENGE)
            reply.setMessageVersion(BR_VERSION)
            reply.data = chunks[0]
            return reply.buildPacket()
        elif packet.messageType == brPacket.brMessageType.CHALLENGE_RES:
            try:
                result = self.secureEnclave.assignedIdentity.decryptChunk(packet.data)
            except:
                logger.warning(f'Challenge failed against node at {nodeRoute.thirdParty.nodeIP} - possible security breach', exc_info=True)
                return False
            
            try:
                check = int(result)
            except:
                logger.warning(f'Challenge failed against node at {nodeRoute.thirdParty.nodeIP} - bad data - Possible attack')
                return False
            
            if check == nodeRoute.routeSecret:
                nodeRoute.setHandShakeComplete()
                if nodeRoute.routeType == nodeRoute.brRouteType.TEST:
                    nodeRoute.upgradeRouteType(brRoute.brRouteType.CONTROL)
                    with self.thrLock:
                        self.inTesting.remove(nodeRoute)
                        self.controlRoutes.append(nodeRoute)
                reply = brPacket()
                reply.setMessageType(brPacket.brMessageType.ENCR_COMMS)
                reply.setMessageVersion(BR_VERSION)
                return reply.buildPacket()
            else:
                logger.warning(f'Response to our challenge was invalid! Their response: {check}')
                return False
        elif packet.messageType == brPacket.brMessageType.CHALLENGE:
            try:
                result = self.secureEnclave.assignedIdentity.decryptChunk(packet.data)
            except:
                logger.warning(f"Failed to decrypt challenge from third party node at {nodeRoute.thirdParty.nodeIP} - possible attack", exc_info=True)
                return False
            sendback = nodeRoute.thirdParty.identity.chunkEncrypt(result)
            reply = brPacket()
            reply.setMessageType(brPacket.brMessageType.CHALLENGE_RES)
            reply.setMessageVersion(BR_VERSION)
            reply.data = sendback[0]
            return reply.buildPacket()
        elif packet.messageType == brPacket.brMessageType.ENCR_COMMS:
            nodeRoute.setHandShakeComplete()
            nodeRoute.encryptionUpgraded = True
            return True
        elif packet.messageType == brPacket.brMessageType.CALLBACK_PING:
            return True

    def __connectionThread__(self, nodeRoute:brRoute, mode:str):

        netAddress = nodeRoute.thirdParty.nodeIP
        netPort = nodeRoute.thirdParty.nodePort
        connection = nodeRoute.assignedConn

        # Statistics gathering
        ourHandledBytes = 0
        ourOutgoingBytes = 0
        ourHandledRequests = 0
        # ----

        # Make sure we have a Public Key from who we are trying to talk to
        if not nodeRoute.thirdPartyPubKeyCheck() and mode != "inbound":
            logger.error("Failed to get a public key. Validation failed, connection canceled.")
            connection.close()
            with self.thrLock:
                self.failedToConnect.append(nodeRoute)
            return


        # Check if we are the initiator and send introduction packet
        if mode == "outbound":
            message = brPacket()
            message.setMessageType(brPacket.brMessageType.INTRODUCE)
            message.setMessageVersion(BR_VERSION)
            ourConfig = f'{self.insecurePort}-{self.nodePort}'.encode('utf-8')
            message.data = ourConfig
            packet = message.buildPacket()
            try:
                connection.send(packet)
                logger.debug(f"Sent introduction packet to {netAddress}")
            except:
                logger.exception("We attempted to initiate the connection and failed to get a proper response!", exc_info=True)
            
            
        nodeRoute.setConnectedState(True)
        
        while not self.shutdown:

            # Attempt to receive data and handle issues
            try:
                rawpacket = connection.recv(1024)  # TODO: Set time-out to kill threads we aren't using
                ourHandledBytes += len(rawpacket)
            except:
                logger.exception("Critical error when receiving data!", exc_info=True)
                break


            try:
                if rawpacket:
                    if nodeRoute.encryptionUpgraded:
                        rawpacket = self.secureEnclave.assignedIdentity.decryptChunk(rawpacket)
                        #TODO: Out of sync encryption when reconnecting to node.
                        #Must find a better way to coordinate 
                    message = brPacket(rawpacket)
                else:
                    logger.info("Got empty packet. This thread will close.")
                    connection.close()
                    break
            except Exception as e:
                logger.exception("Critical error when processing client packet!", exc_info=True)
                break

                
            # Hand off to router to get the full reply
            try:
                reply = self.__router__(message, nodeRoute, mode)
                ourHandledRequests+= 1
            except Exception as e:
                logger.exception("Critical error when processing request!", exc_info=True) # TODO: handle brInvalidMessageType
                break
            
            if reply == False:
                logger.error("Got a false return from the router. Something went wrong. Exiting.")
                connection.close()
                break
            elif reply == True:
                nodeRoute.setRouteStateIdle()
                # We have time to look for messages and news
                
                message = brPacket()
                message.setMessageType(brPacket.brMessageType.CALLBACK_PING)
                message.setMessageVersion(BR_VERSION)
                packet = message.buildPacket()
                reply = nodeRoute.thirdParty.identity.chunkEncrypt(packet)[0]
                time.sleep(1)
            else:
                nodeRoute.setRouteStateBusy()
                if nodeRoute.encryptionUpgraded:
                    reply = nodeRoute.thirdParty.identity.chunkEncrypt(reply)[0]
                
                # Last step of the handshake process. Makes sure that the packet goes out without being encrypted
                if nodeRoute.thirdParty.finishedHandshake == True and nodeRoute.encryptionUpgraded == False:
                    with nodeRoute.routeThreadLock:
                        nodeRoute.encryptionUpgraded = True

            ourOutgoingBytes += len(reply)
            connection.sendall(reply)
                
            # If our route was Idle, send our stats really quick
            if nodeRoute.routeState == "Idle":
                with self.statsLock:
                    self.handledIncomingBytes += ourHandledBytes
                    self.handledOutgoingBytes += ourOutgoingBytes
                    self.respondedToRequests += ourHandledRequests
                    ourHandledBytes = 0
                    ourOutgoingBytes = 0
                    ourHandledRequests = 0
            

        
        # We broke out, find out why!
        if self.shutdown:
            logger.info("Thread got shutdown signal.")
            nodeRoute.setConnectedState(False)
            connection.close()
        else:
            logger.info(f'Thread abnormal shutdown.')
            nodeRoute.setConnectedState(False)
            connection.close()

        
        # Publish our stats really quick
        with self.statsLock:
            self.handledIncomingBytes += ourHandledBytes
            self.handledOutgoingBytes += ourOutgoingBytes
            self.respondedToRequests += ourHandledRequests
        
    def __networkController__(self):
        logger.info("Network controller thread started.")

        # Wait for both the inbound and outbound threads to be started completely...
        while not self.inboundThread.is_alive() and not self.outboundThread.is_alive():
            time.sleep(0.5)
        
        logger.info("Controller repopulating connections...")

        # Startup up procedure
        # Check state of nodes in enclave
        if len(self.knownNodes.keys()) < 1:
            # Lets get our hostname + IP to make sure we don't add ourselves to the seed list
            hostname = socket.gethostname()
            usIP = socket.gethostbyname(hostname)

            if Path('core/seedservers.txt').is_file():
                with open('core/seedservers.txt') as file:
                    for line in file:

                        linesplit = line.split(":")

                        if len(linesplit) == 3:
                            ip = linesplit[0]
                            webport = int(linesplit[1])
                            port = int(linesplit[2])
                        else:
                            ip = line
                            webport = 80
                            port = 443

                        try:
                            socket.inet_aton(ip) # Will fail if it isn't a proper IP address
                            newNodeObject = brNodeRecord()
                            newNodeObject.nodeIP = ip
                            newNodeObject.nodePort = port
                            newNodeObject.webPort = webport
                            with self.connPoolLock:
                                if newNodeObject.queryPubKey():  # TODO: Add check - and ip != usIP
                                    pendingRoute = brRoute(brRoute.brRouteType.TEST, None, newNodeObject)
                                    self.pendingConnect.append(pendingRoute)
                                else:
                                    logger.error(f'Seed server {ip} did not respond correctly when we asked for their public key. (Security Issue?)')
                        except:
                            logger.error(f'A line in the seedservers list is not a valid IP address or seed server. -> {line}')
                logger.info(f"Primed nodes list for new node setup. {len(self.pendingConnect)} connection(s) added for startup.")
        else:
            for nodeIP in self.knownNodes.keys():

                node = self.knownNodes[nodeIP]
                # Since pickle cannot store thread locks, we must be careful and re-populate this
                node.recordThreadLock = threading.Lock()

                pendingRoute = brRoute(brRoute.brRouteType.TEST, None, node)
                with self.connPoolLock:
                    self.pendingConnect.append(pendingRoute)
            logger.info(f'Finished adding {len(self.pendingConnect)} nodes to reconnect to...')

        
        logger.info("Network controller ready.")

        # Local variables for controller

        while not self.shutdown:

            looptime = time.time()
            
            # Scan routes for changes
            for route in self.controlRoutes:
                if route.controllerLastSeen == 0:
                    logger.info(f"Controller is ready to use route-{route.routeID}")
                    route.controllerLastSeenNow()
            
            time.sleep(0.5)
        
        # Broke out, begin shutting down and saving node/route states.
        logger.info("Controller is waiting for all other threads to shut down before saving...")
        while self.inboundThread.is_alive() and self.outboundThread.is_alive():
            time.sleep(0.2)
        
        #TODO: at a later date, make routes restorable
        logger.info("Saving node data - Gathering nodes...")
        for nodeIP in self.knownNodes.keys():
            node:brNodeRecord = self.knownNodes[nodeIP]
            node.setNodeDisconnectedState()
        logger.info("Controller finished saving...")
        
            



