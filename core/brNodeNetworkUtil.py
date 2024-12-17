from enum import IntEnum
import random
import socket
import threading
import time
import uuid

import requests
from core import loggingfactory, notrustvars
from core.brDataBuilder import brPacket

logger = loggingfactory.createNewLogger("brNodeNetwork")

class brNode():
    
    def __init__(self, nodeIP:str, nodePort:int) -> None:
        
        # Net Records
        self.nodeIP:str = None
        self.nodePort:int = 443
        self.webPort:int = 80
        self.controlConnection:brRoute = None
        self.lastLatency = 0
        self.connected = False
        self.completedHandshake = False # If we have completed a handshake at any time
        self.notAccessable = False # True if we cannot make a connection back to the other node. Usually means behind a NAT.

        # Identity
        self.localNodeID = uuid.uuid4()
        self.friendlyName = "Unknown"
        self.identity: notrustvars.enclave.security.identity = None

        # Meta
        self.participatingInRoutes:list[brRoute] = []

    def queryPublicKey(self):
        if self.nodeIP:
            requestURL = f'http://{self.nodeIP}:{str(self.webPort)}/pubkey'
            logger.debug(f"Requesting public key from {requestURL}")
            try:
                response = requests.get(url=requestURL)
            except ConnectionRefusedError:
                logger.error("Connection refused when connecting to get public key.")
                return False
            except:
                logger.exception("Python Requests exception when requesting public key...", exc_info=False)
                return False
            if response.status_code != 200:
                return False
            self.identity = notrustvars.enclave.security.identity.newIdentFromPubImport(response.text)
            logger.debug("Public key has been imported successfully.")
            return True
        else:
            logger.error("IP of node not set. Cannot get pubkey. (Check the code)")
            return False
        
    def addRoute(self, route):
        self.participatingInRoutes.append(route)

    def handshakeUpdateWebPort(self, port):
        if self.completedHandshake == False:
            self.webPort = port

    def handshakeUpdateNodePort(self, port):
        if self.completedHandshake == False:
            self.nodePort = port

class brRoute:

    class brRouteType(IntEnum):
        CONTROL = 0
        TEST = 1
        UNENCRYPTED = 2
        ENCRYPTED = 3
        ONION = 4
        HIGHWAY = 5

    def __init__(self, routeType:brRouteType, assignedConnection:socket.socket, thirdParty:brNode):
        self.routeType = routeType 
        self.routeSecret = random.randrange(0, 1000000)
        self.routeID = uuid.uuid4()
        self.assignedConn:socket.socket = assignedConnection
        self.thirdParty:brNode = thirdParty # Would be the node obj
        self.routeThreadLock = threading.Lock()
        self.timeToLive = 0
        self.controllerLastSeen = 0
        self.encryptionUpgraded = False

        # If we are a hop/control, we won't know these
        self.connectingFrom = None # Client on our end we are connecting
        self.connectingTo = None # Would be the client specifically we created this route for
        # We will know this though
        self.weInitiatedConnection = False

        # Set by nodeManager - Used for encryption/decryption
        self.enclaveInstance:notrustvars.enclave = None

        # Connection updates
        self.newNews = False
        self.news = []
        self.newIncoming = False
        self.inbox = []
        self.newOutgoing = False
        self.outbox = []
        self.routeState = "Unknown"
                
    def setRouteStateIdle(self):
        with self.routeThreadLock:
            self.routeState = "Idle"

    def setRouteStateBusy(self):
        with self.routeThreadLock:
            self.routeState = "Busy"

    def upgradeRouteType(self, brtype:brRouteType):
        with self.routeThreadLock:
            self.routeType = brtype
            self.controllerLastSeen = 0
    
    def controllerLastSeenNow(self):
        with self.routeThreadLock:
            self.controllerLastSeen = time.time()

    def updateSecret(self):
        if self.encryptionUpgraded == False and 

    def routeHandshake(self, insecurePort:int, nodePort:int):

        def receiveAndDecompile() -> brPacket:
            try:
                received = self.assignedConn.recv(1024)
                packet = brPacket.decompile(received)
                return packet
            except:
                logger.exception("Critical error when receiving data!", exc_info=True)
                return False

        def sendIntroAndWait():
            send = brPacket.createIntroPacket()
            packet = send.buildPacket()
            try:
                self.assignedConn.send(packet)
                logger.debug(f"Sent introduction packet to {self.thirdParty.nodeIP}...")
            except:
                logger.exception("We attempted to initiate the connection and failed to get a proper response!", exc_info=True)
                return False
            
            return receiveAndDecompile()

        def processInfoPacket(packet: brPacket):
            thirdPartyData = packet.data
            try:
                decodeData = thirdPartyData.decode('utf-8')
                key = decodeData.split(":")[0]
                value = decodeData.split(":")[1]
            except UnicodeDecodeError:
                logger.exception("Critical error when decoding INFO packet data!", exc_info=True)
                return False
            except:
                logger.exception("Unknown critical error with received INFO packet!", exc_info=True)
                return False
            
            if key == "insport":
                self.thirdParty.handshakeUpdateWebPort(int(value))
            elif key == "nodeport":
                self.thirdParty.handshakeUpdateNodePort(int(value))
  
        def sendInfoPackets():
            insecurePortPayload:brPacket = brPacket.createInfoPacket("insport", str(insecurePort))
            nodePortPayload:brPacket = brPacket.createInfoPacket("nodeport", str(nodePort))
            self.assignedConn.send(insecurePortPayload.buildPacket())
            self.assignedConn.send(nodePortPayload.buildPacket())

        def sendChallenge():
            chunks = self.thirdParty.identity.chunkEncrypt(str(self.routeSecret).encode('utf-8'))
            challenge:brPacket = brPacket.createChallengePacket(chunks[0])
            try:
                self.assignedConn.send(challenge.buildPacket())
                return True
            except:
                logger.exception("Error while sending challenge to remote node!", exc_info=True)
                return False

        def processChallenge(packet:brPacket):
            try:
                decrypted = self.enclaveInstance.assignedIdentity.decryptChunk(packet.data)
                sendback = self.thirdParty.identity.chunkEncrypt(decrypted)
                #newSecret = int(decrypted.decode('utf-8'))
            except:
                logger.exception(f'Challenge failed against node at {self.thirdParty.nodeIP} - bad data - possible attack!', exc_info=True)
                return False

            try:
                response:brPacket = brPacket.createChallengeResponsePacket(sendback)
                self.assignedConn.send(response.buildPacket())
            except:
                logger.exception(f'Error when sending back challenge response!', exc_info=True)
                return False

            return True
            
        def sendReadyAndInfoPackets():
            send = brPacket.createReadyPacket()
            packet = send.buildPacket()
            try:
                self.assignedConn.send(packet)
                logger.debug(f"Sent ready packet to {self.thirdParty.nodeIP}...")
                sendInfoPackets()
                return True
            except:
                logger.exception("Error occured while sending info packets to the connecting remote node!", exc_info=True)
                return False

        def confirmChallenge():
            received = receiveAndDecompile()
            if received.messageType == brPacket.brMessageType.CHALLENGE_RES:
                try:
                    decrypted = self.enclaveInstance.assignedIdentity.decryptChunk(received.data)
                    sentSecret = int(decrypted.decode('utf-8'))
                    if sentSecret == self.routeSecret:
                        return True
                    else:
                        logger.error("Wrong route secret given! Challenge failed!")
                        return False
                except:
                    logger.exception("Bad data while decrypting challenge data! Challenge failed!", exc_info=True)
                    return False
            else:
                logger.error("Received packet in challenge phase was not a challenge response packet!")
                return False


        def outgoingConnectionHandshake():
            # If we are outbound (AKA, reaching out to a node to make this route)
            result = sendIntroAndWait()

            # READY PHASE. Receive INFO packets until CHALLENGE Packet is received.
            if result.messageType == brPacket.brMessageType.READY:

                # Receive related INFO packets
                result = receiveAndDecompile()
                while result.messageType == brPacket.brMessageType.NODE_INFO:
                    processInfoPacket(result)
                    result = receiveAndDecompile()
            else:
                logger.error("Error during handshake. Node didn't send back READY packet.")

            # CHALLENGE PHASE. Receive challenge packet, decrypt and send back encrypted.
            if result.messageType == brPacket.brMessageType.CHALLENGE:
                # Now that we have gotten node_info packets from the remote, we should be able to query the public key
                if self.thirdParty.queryPublicKey() and processChallenge(result):
                    pass
                else:
                    logger.error("Error during handshake. Unable to get public key from remote node to complete challenge.")
                    return False

            else:
                logger.error("Error during handshake. Unexpected packet type after NODE_INFO. (Should be challenge.)")
                return False

        def incomingConnectionHandshake():
            # We are receiving a connection from another node
            
            # Make sure we have the remote nodes public key
            if self.thirdParty.queryPublicKey():
                logger.debug("Confirmed/Received remote node public key...")
            else:
                logger.error("Unable to get Public Key from remote node! Alternate method of confirmation not available yet!")
                return False

            # INTRODUCE PHASE
            result = receiveAndDecompile()
            if result.messageType == brPacket.brMessageType.INTRODUCE:
                if sendReadyAndInfoPackets():
                    logger.debug("Finished intro phase with remote node. Sending challenge...")
                else:
                    logger.error("Something went wrong with our handshake in the intro phase!")
                    return False
            else:
                logger.error(f"Error during handshake. Handshake failed during Introduction phase. Was not introduction packet! ({self.thirdParty.nodeIP})")

            # CHALLENGE PHASE
            if sendChallenge():
                if confirmChallenge():
                    logger.info("Accepted challenge from remote node.")
                else:
                    logger.error("Challenge failed! Closing route!")
                    return False
            else:
                return False

        if self.weInitiatedConnection:
            outgoingConnectionHandshake()
        else:
            incomingConnectionHandshake()



        
class brNodeManager():

    def __init__(self, enclave:notrustvars.enclave) -> None:
        if enclave.isEncKey("brNodeManager"):
            self = enclave.returnData("brNodeManager")
        else:
            self.nodes:dict[str][brNode] = {}
            self.routes:dict[brNode][brRoute] = {}
            self.routesFailed:list[brRoute] = []
        self.enc = enclave

        # Do not store in enclave
        self.thrLock = threading.Lock()
        self.pendingConnectionRequests:list[brRoute] = []
        
    def acceptConnection(self, connection:socket.socket, address:tuple, initiatedConnection=False) -> brRoute:
        
        if address[0] not in self.nodes.keys():
            newNode = brNode(address[0], address[1])
            testRoute = brRoute(brRoute.brRouteType.TEST, connection, newNode)
            testRoute.weInitiatedConnection = initiatedConnection
            testRoute.enclaveInstance = self.enc
            newNode.addRoute(testRoute)
            self.nodes[address[0]] = newNode
            self.routes[newNode] = testRoute
            return testRoute
        else:
            node:brNode = self.nodes[address[0]]
            newRoute = brRoute(brRoute.brRouteType.TEST, connection, node)
            newRoute.weInitiatedConnection = initiatedConnection
            newRoute.enclaveInstance = self.enc
            node.addRoute(newRoute)
            return newRoute
        
    def submitConnectionRequest(self, address:tuple):
        with self.thrLock:
            self.pendingConnectionRequests.append(address)


    def getConnectionRequest(self, pop=False):
        if pop:
            if len(self.pendingConnectionRequests) > 0:
                with self.thrLock:
                    route = self.pendingConnectionRequests.pop()
                return route
            else:
                return False
        else:
            if len(self.pendingConnectionRequests) > 0:
                return True
            else:
                return False
    
    def submitFailedRoute(self, route:brRoute):
        self.routesFailed.append(route)
        logger.info(f"Submitted failed route. {len(self.routesFailed)} failed routes in list.")