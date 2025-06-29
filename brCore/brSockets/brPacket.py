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
        READY = 1
        NODE_INFO = 2       # Used to exchange info about the node. One way.
        CHALLENGE = 3
        CHALLENGE_RES = 4

        # Encryption
        ENCR_COMMS = 5      # Sent when nodes finally upgrade to encrypted communications

        # Utility
        ASK_FOR_FRIENDS = 6
        FRIEND_ANNOUNCE = 7
        PING = 8
        CALLBACK_PING = 9   # Absolute Solver - Used to provide a window for response
        UR_BEHIND_NAT = 10  # Message type to send when we think a remote node is behind a NAT.

        # Message Handling
        NEW_MESSAGE = 11    # Packet will contain the number of packets after this one to be received
        READY_MESSAGE = 12  # Response that we are ready to receive sequence
        MESSAGE = 13        # Data to receive
        
        
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
            self.data = receivedPacket[15:]
        else:
            self.messageType:int = None
            self.version:str = BR_VERSION
            self.altIP: str = None
            self.altPub: str = None
            self.toClient: str = None
            self.fromClient: str = None
            self.contentLength: int = None
            self.data: bytes = b''
            
    def setMessageType(self, msgdesc:int):
        if msgdesc in brPacket.brMessageType:
            self.messageType = msgdesc
            return self
        else:
            pass # Raise exception 

    def setMessageVersion(self, version:str):
        self.version = version.encode("utf-8").ljust(14, b'\0')

    def buildPacket(self):
        messageType = self.messageType.to_bytes(1)
        self.setMessageVersion(BR_VERSION)
        version = self.version
        # Pre-flight check

        if len(messageType) != 1:
            raise brPacket.brInvalidMessageType(f'Message type data: {messageType}')


        packet = messageType + version + self.data
        return packet
    
    def createSimpleHello(self):
        self.messageType = self.brMessageType.INTRODUCE.value
        return self.buildPacket()
    
    def createSimpleReady(self):
        self.messageType = self.brMessageType.READY.value
        return self.buildPacket()