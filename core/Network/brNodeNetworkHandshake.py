import socket
<<<<<<< HEAD:core/Network/brNodeNetworkHandshake.py
from core.Logging import loggingfactory
=======
from core import BR_VERSION, loggingfactory
>>>>>>> refs/remotes/origin/dev-modular-expansion:core/brNodeNetworkHandshake.py
from core.brDataBuilder import brPacket
import logging

from core.brNodeNetworkUtil import brNode, brRoute

logger = loggingfactory.createNewLogger("brNodeNetworkHandshakes")
outboundlogger = loggingfactory.createNewLogger("brNodeNetworkOutboundConn")
inboundlogger = loggingfactory.createNewLogger("brNodeNetworkInboundConn")

class commonNetworkFunctions:

    def sendDataToConnection(packet:brPacket, connection:socket.socket):
        try:
            connection.sendall(packet)
            return True
        except Exception as e:
            logger.exception(f"Failed to send data to {connection.getpeername()}", exc_info=True)
            return False

    def receiveAndDecompile(connection:socket.socket):
        try:
            packet = connection.recv(1024)
            return brPacket.decompile(packet)
        except Exception:
            logger.exception(f"Error when we expected to receive data from {connection.getpeername()}", exc_info=True)

    def sendIntroAndWait(connection:socket.socket):
        # Send intro packet
        tosend = brPacket.createIntroPacket()
        packet = tosend.buildPacket()
        if commonNetworkFunctions.sendDataToConnection(packet, connection):
            return True
        else:
            logger.error("Was unable to send Intro packet due to previous error. Handshake failed.")
            return False
    
    def sendReady(connection:socket.socket):
        tosend = brPacket.createReadyPacket()
        packet = tosend.buildPacket()
        if commonNetworkFunctions.sendDataToConnection(packet, connection):
            return True
        else:
            logger.error("Was unable to send Ready packet due to previous error. Handshake failed.")
            return False
        
    def sendInfoPacket(infoname, data, connection:socket.socket):
        tosend = brPacket.createInfoPacket(infoname, data)
        packet = tosend.buildPacket()
        if commonNetworkFunctions.sendDataToConnection(packet, connection):
            return True
        else:
            logger.error("Was unable to send Info packet due to previous error. Handshake failed.")
            return False
        
    def receiveAndExpect(connection:socket.socket, packetTypes: list[brPacket.brMessageType]):
        packet: brPacket = commonNetworkFunctions.receiveAndDecompile(connection)
        if packet.messageType in packetTypes:
            return packet
        else:
            logger.error(f"We expected any of these brPacket types: {packetTypes} as per our protocol, but got {packet.messageType} !")
            return False
        
    def evalPacketType(evalpacket:brPacket, acceptedTypes: list[brPacket.brMessageType]):
        if evalpacket.messageType in acceptedTypes:
            return True
        else:
            logger.error(f"Evaluation of packet type failed. We expected any of these: {acceptedTypes} but got {evalpacket.messageType}")
            return False


class alpha0001_handshake:
    
    def __init__(self, route:brRoute, nodeInfo = {}):
        self.route = route
        self.completed = False
        self.connection = self.route.thirdParty.controlConnection
        self.required_handshake_version = "Unknown"
        self.nodeInfo = nodeInfo
        self.modelogger:logging.Logger = None

    def processInfoPacket(self, packet: brPacket):
        log = self.modelogger
        thirdPartyData = packet.data
        try:
            decodeData = thirdPartyData.decode('utf-8')
            key = decodeData.split(":")[0]
            value = decodeData.split(":")[1]
        except UnicodeDecodeError:
            log.exception("Critical error when decoding INFO packet data!", exc_info=True)
            return False
        except:
            log.exception("Unknown critical error with received INFO packet!", exc_info=True)
            return False
        
        if key == "insport":
            self.nodeInfo[key] = int(value)
            self.route.thirdParty.handshakeUpdateWebPort(int(value))
            log.info(f"Node advertized their insecure web port as: {int(value)}")
            return True
        elif key == "nodeport":
            self.nodeInfo[key] = int(value)
            self.route.thirdParty.handshakeUpdateNodePort(int(value))
            log.info(f"Node advertized their node port as: {int(value)}")
            return True
        
        log.warning("Extra data was sent in an info packet. This may have been corrupt data, or a possible security poke.")  
        

    def handshake(self, outgoing:bool):
        if outgoing:
            self.initiate()
        else:
            self.receive()

    def initiate(self):
<<<<<<< HEAD:core/Network/brNodeNetworkHandshake.py
        commonNetworkFunctions.sendIntroAndWait(self.connection)
        
        
    def receive(self):
        packet = commonNetworkFunctions.receiveAndDecompile(self.connection)
=======
        self.modelogger = outboundlogger
        log = self.modelogger

        # Send out an intro packet and see how the 3rd party reacts
        if commonNetworkFunctions.sendIntroAndWait(self.connection):
            log.debug("Sent introduction packet. Waiting for response...")
        else:
            return False
        
        # Wait for and receive ready. If we disconnect here, there is a possibility that the other side disconnected
        # Because we don't support their protocol.

        # Otherwise, once we get a ready packet, we can receive info packets from third party so we know how to connect and such.
        if commonNetworkFunctions.receiveAndExpect(self.connection, [brPacket.brMessageType.READY]):
            log.debug("Ready packet was received from third party. Accepting info packets.")
            packet:brPacket = commonNetworkFunctions.receiveAndExpect(self.connection, [brPacket.brMessageType.CHALLENGE, brPacket.brMessageType.NODE_INFO])
            while commonNetworkFunctions.evalPacketType(packet, [brPacket.brMessageType.CHALLENGE, brPacket.brMessageType.NODE_INFO]):
                if packet.messageType == brPacket.brMessageType.NODE_INFO:
                    if not self.processInfoPacket(packet):
                        return False
                if packet.messageType == brPacket.brMessageType.CHALLENGE:
                    break
        
        # Breaking out - We have received our info packets and have a challenge packet.
        
        # With a challenge, we need to make sure we have their current public key.
        if not self.route.thirdParty.queryPublicKey():
            log.error("Node didn't respond correctly when asked about it's public key. See previous errors. Handshake failed.")

        # Now process the challenge
        try:
            
            decrypted = self.route.enclaveInstance.assignedIdentity.decryptChunk(packet.data)
            sendback = self.route.thirdParty.identity.chunkEncrypt(decrypted)
            #newSecret = int(decrypted.decode('utf-8'))
        except:
            log.exception(f'Challenge failed against node at {self.route.thirdParty.nodeIP} - bad data - possible attack!', exc_info=True)
            return False

        try:
            response:brPacket = brPacket.createChallengeResponsePacket(sendback)
            self.connection.send(response.buildPacket())
        except:
            logger.exception(f'Error when sending back challenge response!', exc_info=True)
            return False
        

                
            
       
    def receive(self):
        self.modelogger = outboundlogger
        log = self.modelogger

        # We received an incoming connection - Receive the incoming packet
        packet: brPacket = commonNetworkFunctions.receiveAndDecompile(self.connection)
        if packet.version != "0.0.1-alpha":
            log.debug(f"Connection requires protocol upgrade to: {packet.version}")
            return False
        else:
            log.debug(f"Advertized protocol is compliant with version: {BR_VERSION}")

        # Now that we know the protocol is correct, let's send a ready packet.
        if not commonNetworkFunctions.sendReady(self.connection):
            log.error("Failed to send a ready packet. Handshake has failed.")

        # We must send them our info packets now. They will be waiting for them until our challenge packet
        if not commonNetworkFunctions.sendInfoPacket("insport", self.nodeInfo["insport"], self.connection):
            log.error("Unable to send first Info packet. Handshake failed.")

        if not commonNetworkFunctions.sendInfoPacket("nodeport", self.nodeInfo["nodeport"], self.connection):
            log.error("Unable to send second Info packet. Handshake failed.")

        # Now send our challenge
        chunks = self.route.thirdParty.identity.chunkEncrypt(str(self.route.routeSecret).encode('utf-8'))
        challenge:brPacket = brPacket.createChallengePacket(chunks[0])
        if not commonNetworkFunctions.sendDataToConnection(challenge, self.connection):
            log.error("Failed on sending challenge to third party. Handshake failed.")



>>>>>>> refs/remotes/origin/dev-modular-expansion:core/brNodeNetworkHandshake.py

