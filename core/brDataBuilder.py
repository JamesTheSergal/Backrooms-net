from enum import IntEnum
import pprint
from . import BR_VERSION


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

        # First phase introduction
        INTRODUCE = 0
        CHALLENGE = 1
        CHALLENGE_RES = 2

        
        ENCR_COMMS = 3      # Sent when nodes finally upgrade to encrypted communications
        NODE_INFO = 4       # Used to exchange info about the node. One way.
        ASK_FOR_FRIENDS = 5
        FRIEND_ANNOUNCE = 6
        PING = 7
        CALLBACK_PING = 8   # Absolute Solver - Used to provide a window for response
        NEW_MESSAGE = 9     # Packet will contain the number of packets after this one to be received
        READY_MESSAGE = 10  # Response that we are ready to receive sequence
        MESSAGE = 11        # Data to receive

    def decompile(receivedPacket:bytes):

        newpacket = brPacket()

        if receivedPacket is not None:
            messageType = receivedPacket[0]
            if messageType in brPacket.brMessageType:
                newpacket.messageType = messageType
            else:
                raise brPacket.brInvalidMessageType(messageType) 
            version = receivedPacket[1:15]
            newpacket.version = version.lstrip(b'\0').decode('utf-8')
            newpacket.data = receivedPacket[15:]
        else:
            return False
        
        return newpacket

    def __init__(self) -> None:
        self.messageType:int = None
        self.version:str = BR_VERSION
        self.altIP: str = None
        self.altPub: str = None
        self.toClient: str = None
        self.fromClient: str = None
        self.data: bytes = b''
            
    def setMessageType(self, msgdesc:int):
        if msgdesc in brPacket.brMessageType:
            self.messageType = msgdesc
            return self
        else:
            pass # Raise exception 

    def buildPacket(self) -> bytes:
        messageType = self.messageType.to_bytes(1, byteorder='little')
        version = self.version.encode("utf-8").ljust(14, b'\0')
        # Pre-flight check

        if len(messageType) != 1:
            raise brPacket.brInvalidMessageType(f'Message type data: {messageType}')


        packet = messageType + version + self.data
        return packet
    
    def createIntroPacket():
        packet = brPacket()
        packet.setMessageType(brPacket.brMessageType.INTRODUCE)
        return packet
    
    def createInfoPacket(name:str, value:str):
        packet = brPacket()
        packet.setMessageType(brPacket.brMessageType.NODE_INFO)
        data = f'{name}:{value}'.encode('utf-8')
        packet.data = data
        return packet
    
    def createReadyPacket():
        packet = brPacket()
        packet.setMessageType(brPacket.brMessageType.READY)
        return packet
    
    def createChallengeResponsePacket(data:bytes):
        packet = brPacket()
        packet.data = data
        packet.setMessageType(brPacket.brMessageType.CHALLENGE_RES)
        return packet
    
    def createChallengePacket(data:bytes):
        packet = brPacket()
        packet.data = data
        packet.setMessageType(brPacket.brMessageType.CHALLENGE)
        return packet