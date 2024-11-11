from enum import IntEnum
import logging
from pathlib import Path
import pprint
import socket
import os
import threading
import uuid
from core import loggingfactory, notrustvars
from node import BR_VERSION

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
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
        
    class brInvalidMessageType(backroomsProtocolException):
        """Exception raised when an invalid message type is invoked."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Invalid message type! (Data Involved) ->"
            self.data = data
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
        
    class brInvalidVersion(backroomsProtocolException):
        """Exception raised when an invalid version format is used."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Invalid version format! Ensure size is not exceeded! (Data Involved) ->"
            self.data = data
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
        
    class brPreFlightCheckFailure(backroomsProtocolException):
        """Exception raised when a preflight check for the packet fails."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Pre-Flight check failed! (Data Involved) ->"
            self.data = data
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"

    class brMessageType(IntEnum):
        INTRODUCE = 0
        CHALLENGE = 1
        CHALLENGE_RES = 2
        ASK_FOR_FRIENDS = 3
        FRIEND_ANNOUNCE = 4
        CONN_TEST = 5
        CALLBACK_PING = 6 # Absolute Solver
        MESSAGE = 7

    def __init__(self, receivedPacket:bytes=None) -> None:
        if receivedPacket is not None:
            pass
        else:
            pass

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

    def buildPacket(self):
        messageType = self.messageType.to_bytes(1, byteorder='little')
        version = self.version.encode("utf-8")
        altIP = self.altIP.encode("utf-8")
        toClient = self.toClient.encode("utf-8")
        fromClient = self.fromClient.encode("utf-8")

        # Pre-flight check

        if len(messageType) != 1:
            raise brPacket.brInvalidMessageType(f'Message type data: {messageType}')


        packet = messageType + version + altIP + toClient + fromClient
        return packet
    

    
        


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
        self.nodePort = nodePort
        # ------------

        # Connection Pool
        self.connections = []
        # ------------

        # Threads
        self.mainThread:threading.Thread = None
        self.webThreads:list[threading.Thread] = []
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
        logger.info("Started node server.")
        if not self.running:
            self.mainThread = threading.Thread(name="brNodeNetworkeMain", target=self.__mainLoop__, args=[])
            self.mainThread.start()

    def shutdownServer(self):
        self.shutdown = True
        logger.info("Sent shutdown signal - Node Main Thread is now waiting...")
        self.mainThread.join()

    def __mainLoop__(self):
        self.running = True

        try:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soc.bind((self.bindAddress, self.nodePort))
            soc.listen(4)
            soc.settimeout(1.0)
        except Exception as e:
            logger.exception("Error occured when creating socket!", exc_info=True)
            self.running = False
            return
        
        while self.shutdown is False:
            try:
                connection, address = soc.accept()
                spawnThread = threading.Thread(target=self.__connectionThread__, args=[connection, address])
                self.webThreads.append(spawnThread)
                spawnThread.start()
            except socket.timeout:
                # This is normal. It gives us time to loop and check threads.

                deadThreads = []
                for thr in self.webThreads:
                    if not thr.is_alive():
                        deadThreads.append(thr)

                for thr in deadThreads:
                    self.webThreads.remove(thr)
        
        # Broke out of loop. We must be shutting down.
        logger.info("Main Node loop received shutdown, refusing new connections.")
        logger.info(f'Waiting for {len(self.webThreads)} threads to shutdown...')

        while len(self.webThreads) > 0:
            logger.info(f'Waiting for {len(self.webThreads)} threads to shutdown...')
            for thr in self.webThreads:
                thr.join(timeout=5.0)
                if not thr.is_alive():
                    logger.info(f'Thread {thr.native_id} shutdown...')
                    self.webThreads.remove(thr)
                
        logger.info("All threads closed. Exiting main loop.")

    def __debugToFile__(data: bytes, id, count):
        tempdir = Path(f'temp/{id}')
        if not tempdir.is_dir():
            os.mkdir(f'temp/{id}')
        with open(f'temp/{id}/{str(count)}.packet', 'ab') as df:
            df.write(data)
        logger.debug(f'Wrote packet to: temp/{id}/{str(count)}.packet')

    def __connectionThread__(self, connection: socket.socket, address):

        netAddress = address[0]
        netPort = address[1]
        debugCount = 0
        debugID = uuid.uuid4()
        ourHandledBytes = 0
        ourOutgoingBytes = 0
        ourHandledRequests = 0
        ourErrors = 0

        # Make sure we do a Thread Safe lock! 
        with self.thrLock:
            self.connections.append(connection)
        
        logger.info(f'Accepted connection from {netAddress}:{netPort}')

        while not self.shutdown:

            # Attempt to receive data and handle issues
            try:
                rawpacket = connection.recv(1024)
            except:
                break
            # Finished handling exceptions

            if self.debug:
                brNodeServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount += 1

            # Processing here --

            # Parse the packet to get key details
            try:
                parsingResult = brNodeServer.packetParser(connection, rawpacket)
            except Exception as e:
                logger.exception("Critical error when processing client packet!", exc_info=True)
                brNodeServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount+= 1
                ourErrors+= 1
                packet = self.__handleServerError__()

            # Hand off to router to get the full reply
            try:
                reply = self.__router__(parsingResult)

                # After we go through the router, we should be able to get an accurate measure of bytes handled
                ourHandledBytes += parsingResult.totalSize

                packet = reply.setBodySize().buildPacket()
            except Exception as e:
                logger.exception("Critical error when processing request!", exc_info=True)
                brNodeServer.__debugToFile__(rawpacket, debugID, debugCount)
                debugCount+= 1
                ourErrors+= 1
                packet = self.__handleServerError__()


            # End of processing

            brNodeServer.__debugToFile__(packet, debugID, debugCount)
            debugCount += 1
            connection.sendall(packet)
            ourHandledRequests+= 1
            ourOutgoingBytes+= len(packet)
            

        
        # We broke out, find out why!
        if self.shutdown:
            logger.info("Thread got shutdown signal.")
        else:
            if self.debug:
                logger.info(f'Thread shutting down - Handled {debugCount} packets.')
            else:
                logger.info(f'Thread shutting down.')
        
        # Publish our stats really quick
        with self.statsLock:
            self.handledIncomingBytes += ourHandledBytes
            self.handledOutgoingBytes += ourOutgoingBytes
            self.respondedToRequests += ourHandledRequests
            self.errors += ourErrors

        with self.thrLock:
            self.connections.remove(connection)


