from enum import IntEnum
import logging
from pathlib import Path
import pprint
import socket
import os
import threading
import time
import uuid
import requests
from core import loggingfactory, notrustvars
#from node import BR_VERSION

BR_VERSION = "0.0.1-alpha"

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

class brPacket:

    class backroomsProtocolException(Exception):
        pass

    class brPacketOversize(backroomsProtocolException):
        """Exception is raised when the packet is larger than the max allowed by the protocol."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Data is oversized. (Overflow? Security Violation?) (Data Involved) ->"
            self.data = data
            super().__init__(self.message, self.data)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
        
    class brInvalidMessageType(backroomsProtocolException):
        """Exception raised when an invalid message type is invoked."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Invalid message type! (Data Involved) ->"
            self.data = data
            super().__init__(self.message, self.data)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
        
    class brInvalidVersion(backroomsProtocolException):
        """Exception raised when an invalid version format is used."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Invalid version format! Ensure size is not exceeded! (Data Involved) ->"
            self.data = data
            super().__init__(self.message, self.data)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
        
    class brPreFlightCheckFailure(backroomsProtocolException):
        """Exception raised when a preflight check for the packet fails."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Pre-Flight check failed! (Data Involved) ->"
            self.data = data
            super().__init__(self.message, self.data)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"

    class brMessageType(IntEnum):
        INTRODUCE = 0
        CHALLENGE = 1
        CHALLENGE_RES = 2
        ASK_FOR_FRIENDS = 3
        FRIEND_ANNOUNCE = 4
        CALLBACK_PING = 5 # Absolute Solver
        READY_MESSAGE = 6
        MESSAGE = 7

    def __init__(self, receivedPacket:bytes=None) -> None:

        if receivedPacket is not None:
            # Start processing packet.
            messageType = receivedPacket[0]
            if messageType in brPacket.brMessageType:
                self.messageType = messageType
            else:
                raise brPacket.brInvalidMessageType(messageType) 
            version = receivedPacket[1:15]
            self.version = version.lstrip(b'\0').decode('utf-8')
        else:
            self.messageType:int = None
            self.version:str = BR_VERSION
            self.altIP: str = None
            self.altPub: str = None
            self.toClient: str = None
            self.fromClient: str = None
            self.data: bytes = None

    def setMessageType(self, msgdesc:int):
        if msgdesc in brPacket.brMessageType:
            self.messageType = msgdesc
            return self
        else:
            pass # Raise exception 

    def setMessageVersion(self, version:str):
        self.version = version.encode("utf-8").ljust(14, b'\0')

    def buildPacket(self):
        messageType = self.messageType.to_bytes(1, byteorder='little')
        version = self.version
        # Pre-flight check

        if len(messageType) != 1:
            raise brPacket.brInvalidMessageType(f'Message type data: {messageType}')


        packet = messageType + version
        return packet
    
class brNodeRecord:

    def __init__(self):
        self.nodeIP:str = None
        self.nodePort:int = 443
        self.webPort:int = 80
        self.identity: notrustvars.enclave.security.identity
        self.lastLatency = 0
        self.connected = False
        self.finishedHandshake = False

    def queryPubKey(self):
        if self.nodeIP:
            logger.debug(f"Requesting public key from {self.nodeIP}")
            try:
                response = requests.get(f'http://{self.nodeIP}:{self.webPort}/pubkey')
            except:
                logger.error("Python Requests exception when requesting public key...")
                return False
            if response.status_code != 200:
                return False
            nodeident = notrustvars.enclave.security.identity.newIdentFromPubImport(response.text)
            self.identity = nodeident
            return True
        else:
            logger.error("IP of node not set. Cannot get pubkey. (Check the code)")
            return False

    
class brNodeServer:

    class brNodeServerException(Exception):
        """Exception base class for the brWebServer."""
        pass

    def __init__(self, secureEnclave:notrustvars.enclave, bindAddress:str="127.0.0.1", nodePort:int=443, debug=False) -> None:

        # If debug is set, we will log at the lowest level + debug timings
        self.debug = debug
        # ------------

        # Network setup
        self.bindAddress = bindAddress
        self.nodePort:int = nodePort
        # ------------

        # Secure Enclave for peer stats
        self.secureEnclave = secureEnclave
        # ------------

        # Connection Pool
        self.pendingConnect:list[brNodeRecord] = [] # pending outgoing connections - Not inbound
        self.inboundConnections = []
        self.outboundConnections = []
        # ------------

        # Threads
        self.inboundThread:threading.Thread = None
        self.outboundThread:threading.Thread = None
        self.inboundNodeThreads:list[threading.Thread] = []
        self.outboundNodeThreads:list[threading.Thread] = []
        self.thrLock = threading.Lock()
        # ------------

        # server state flags
        self.running = False
        self.shutdown = False
        # ------------

        # Stats
        self.statsLock = threading.Lock()
        self.handledIncomingBytes = 0
        self.handledOutgoingBytes = 0
        self.respondedToRequests = 0
        self.errors = 0
        # ------------

    def startServer(self):

        if not self.secureEnclave.isEncKey("knownNodes"):

            # Lets get our hostname + IP to make sure we don't add ourselves to the seed list
            hostname = socket.gethostname()
            usIP = socket.gethostbyname(hostname)

            primer = []
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
                            if newNodeObject.queryPubKey():  # TODO: Add check - and ip != usIP
                                primer.append(newNodeObject)
                            else:
                                logger.error(f'Seed server {ip} did not respond correctly when we asked for their public key. (Security Issue?)')
                        except:
                            logger.error(f'A line in the seedservers list is not a valid IP address or seed server. -> {line}')
                self.secureEnclave.insertData("knownNodes", primer)
                logger.info("Primed nodes list for new node setup.")
        
        else:
            nodeList:list[brNodeRecord] = self.secureEnclave.returnData("knownNodes")
            for node in nodeList:
                node.connected = False
                node.lastLatency = 0
                self.pendingConnect.append(node)
            logger.info(f'Will reconnect to {len(nodeList)} known nodes on startup...')
            

        logger.info("Started node server.")
        if not self.running:
            self.inboundThread = threading.Thread(name="brNodeNetworkInbound", target=self.__inboundLoop__, args=[])
            self.outboundThread = threading.Thread(name="brNodeNetworkOutbound", target=self.__outboundLoop__, args=[])
            self.inboundThread.start()
            self.outboundThread.start()

    def shutdownServer(self):
        self.shutdown = True
        logger.info("Sent shutdown signal - Node Main Thread is now waiting...")
        self.inboundThread.join()
        self.outboundThread.join()

    def __inboundLoop__(self):
        self.running = True
        
        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((self.bindAddress, self.nodePort))
            soc.listen(4)
            soc.settimeout(0.5)
        except Exception as e:
            logger.exception("Error occured when creating socket!", exc_info=True)
            self.running = False
            return
        
        while self.shutdown is False:

            # Handle incoming first
            try:
                connection, address = soc.accept()
                tempNode = brNodeRecord()
                tempNode.nodeIP = address
                spawnThread = threading.Thread(name=f'brNodeCon-inbound-({address})',target=self.__connectionThread__, args=[tempNode, connection, address, "inbound"])
                self.inboundNodeThreads.append(spawnThread)
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
                outNode = self.pendingConnect.pop()
                try:
                    obsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    logger.debug("Attempting to connect to node...")
                    obsoc.connect((outNode.nodeIP, outNode.nodePort))
                    spawnThread = threading.Thread(name=f'brNodeCon-outbound-({outNode.nodeIP})',target=self.__connectionThread__, args=[outNode, obsoc, outNode.nodeIP, "outbound"])
                    self.outboundNodeThreads.append(spawnThread)
                    spawnThread.start()
                    logger.debug("Connected.")
                except:
                    logger.exception("Cannot connect to node!", exc_info=True)
            else:

                # Dead thread sweep
                deadThreads = []
                for thr in self.outboundNodeThreads:
                    if not thr.is_alive():
                        deadThreads.append(thr)

                for thr in deadThreads:
                    self.outboundNodeThreads.remove(thr)


                time.sleep(0.05)
        
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

    def __router__(self, packet: brPacket, nodeIdent:brNodeRecord):
        if packet.messageType == brPacket.brMessageType.INTRODUCE:
            logger.debug(f"Received introduction packet from node at {nodeIdent.nodeIP}! Success!!!")
            return True

    def __connectionThread__(self, nodeIdent:brNodeRecord, connection: socket.socket, address, mode:str):

        netAddress = address[0]
        netPort = address[1]

        # Statistics gathering
        debugCount = 0
        debugID = uuid.uuid4()
        ourHandledBytes = 0
        ourOutgoingBytes = 0
        ourHandledRequests = 0
        ourErrors = 0
        # ----

        # Make sure we do a Thread Safe lock! 
        with self.thrLock:
            if mode == "inbound":
                logger.debug(f'Accepted inbound connection from {netAddress}:{netPort}')
                self.inboundConnections.append(connection)
            elif mode == "outbound":
                logger.debug(f'Accepted outbound connection from {netAddress}:{netPort}')
                self.outboundConnections.append(connection)

        # Check if we are the initiator and send introduction packet
        if mode == "outbound":
            message = brPacket()
            message.setMessageType(brPacket.brMessageType.INTRODUCE)
            message.setMessageVersion(BR_VERSION)
            packet = message.buildPacket()
            brNodeServer.__debugToFile__(packet, debugID, debugCount)
            debugCount += 1
            connection.send(packet)
        
        
        while not self.shutdown:

            # Attempt to receive data and handle issues
            try:
                rawpacket = connection.recv(1024)
            except:
                break

            if self.debug:
                brNodeServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount += 1

            try:
                if rawpacket:
                    message = brPacket(rawpacket)
                else:
                    logger.info("Got empty packet. This thread will close.")
                    connection.close()
                    break
            except Exception as e:
                logger.exception("Critical error when processing client packet!", exc_info=True)
                #brNodeServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount+= 1
                ourErrors+= 1
                

            # Hand off to router to get the full reply
            try:
                pass
                reply = self.__router__(message, nodeIdent)

                # After we go through the router, we should be able to get an accurate measure of bytes handled
                #ourHandledBytes += parsingResult.totalSize

                #packet = reply.setBodySize().buildPacket()
            except Exception as e:
                logger.exception("Critical error when processing request!", exc_info=True)
                #brNodeServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount+= 1
                ourErrors+= 1
                


            # End of processing

            #brNodeServer.__debugToFile__(packet, debugID, debugCount)
            debugCount += 1
            #connection.sendall(packet)
            connection.close()
            #ourHandledRequests+= 1
            #ourOutgoingBytes+= len(packet)
            

        
        # We broke out, find out why!
        if self.shutdown:
            logger.info("Thread got shutdown signal.")
        else:
            if self.debug:
                logger.info(f'Thread shutting down - Handled {debugCount} packets.')
            else:
                logger.info(f'Thread shutting down.')
        
        # Publish our stats really quick
        #with self.statsLock:
        #    self.handledIncomingBytes += ourHandledBytes
        #    self.handledOutgoingBytes += ourOutgoingBytes
        #    self.respondedToRequests += ourHandledRequests
        #    self.errors += ourErrors

        with self.thrLock:
            if mode == "inbound":
                self.inboundConnections.remove(connection)
            elif mode == "outbound":
                self.outboundConnections.remove(connection)


