from enum import IntEnum
import pickle
import pprint

from . import BR_VERSION

class brPacket:
    
    MAX_DATA_BYTES = 1483
    VALID_VERSIONS = ["0.0.1-alpha"]

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
    
    class brInvalidContentLength(backroomsProtocolException):
        """Exception raised when there is an issue with content length."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Content Length! (Data Involved) ->"
            self.data = data
            super().__init__(self.message, self.data)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
    
    class brInvalidVersion(backroomsProtocolException):
        """Exception raised when an invalid version format is used."""

        def __init__(self, data) -> None:
            self.message = "Backrooms Protocol violation. Invalid version format! (Data Involved) ->"
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
        INCREASE_ENCR = 3   # To notify the node that we are increasing coms
        CHALLENGE = 4
        CHALLENGE_RES = 5

        # Encryption
        ENCR_COMMS = 6      # Sent when nodes finally upgrade to encrypted communications

        # Utility
        ASK_FOR_FRIENDS = 7
        FRIEND_ANNOUNCE = 8
        PING = 9
        CALLBACK_PING = 10   # Absolute Solver - Used to provide a window for response
        UR_BEHIND_NAT = 11  # Message type to send when we think a remote node is behind a NAT.

        # Message Handling
        NEW_MESSAGE = 12    # Packet will contain the number of packets after this one to be received
        READY_MESSAGE = 13  # Response that we are ready to receive sequence
        MESSAGE = 14        # Data to receive
        
        
    def __init__(self, receivedPacket:bytes=None) -> None:

        if receivedPacket is not None:
            # Check Message type first
            messageType = receivedPacket[0]
            if messageType in brPacket.brMessageType:
                self.messageType = self.brMessageType(messageType)
            else:
                raise brPacket.brInvalidMessageType(messageType) 
            
            # Check for valid version
            version = receivedPacket[1:15]
            try:
                self.version = version.lstrip(b'\0').rstrip(b'\0').decode('utf-8')
            except:
                raise self.brInvalidVersion(f"Received bad version data: {version}")
            
            # Check against known version
            if self.version not in self.VALID_VERSIONS:
                raise self.brInvalidVersion(f"Received packet version is invalid or not recognized: {self.version}")
            
            # Check content length
            try:
                self.contentLength = int.from_bytes(receivedPacket[16:17])
            except:
                raise self.brInvalidContentLength(f"Invalid Data: {receivedPacket[16:17]}")
            
            # Check content length bounds
            if self.contentLength > self.MAX_DATA_BYTES:
                raise self.brInvalidContentLength(f"Content length too long: {self.contentLength}")
            
            self.data = receivedPacket[17:]
        else:
            self.messageType:brPacket.brMessageType = None
            self.version:str = BR_VERSION
            self.contentLength: int = 0
            self.data: bytes = b''
    
    def setAllFieldsToBytes(self):
        if self.messageType is None:
            raise self.brInvalidMessageType("Message type was not specified.")
        
        self.messageType = self.messageType.to_bytes(1)
        self.contentLength = self.contentLength.to_bytes(2)
        self.version = self.version.encode("utf-8").ljust(14, b'\0')


    def setMessageType(self, msgdesc:int):
        if msgdesc in brPacket.brMessageType:
            self.messageType = msgdesc
            return self
        else:
            pass # Raise exception 
        
    def insertObject(self, insertdata:any):
        objdata = pickle.dumps(insertdata)
        if len(objdata) <= self.MAX_DATA_BYTES:
            self.contentLength = len(objdata)
            self.data = objdata
        else:
            raise self.brPacketOversize()
        
    def rebuildObject(self):
        objdata = pickle.loads(self.data)
        return objdata

    def buildPacket(self, msgType:brMessageType=None) -> bytes:

        if msgType is not None:
            self.setMessageType(msgType.value)
            
        # Convert everything to bytes
        
        self.setAllFieldsToBytes()
        
        # Pre-flight check

        if self.messageType is None or len(self.messageType) != 1:
            raise brPacket.brInvalidMessageType(f'Message type data: {self.messageType}')

        header = self.messageType + self.version + self.contentLength
        
        if len(header) != 17:
            raise self.brPreFlightCheckFailure(f"Header length is not 17 bytes! Header: {header}")
        
        packet = header + self.data
        
        return packet
    
    def createSimpleHello(self):
        return self.buildPacket(brPacket.brMessageType.INTRODUCE)
    
    def createSimpleReady(self):
        return self.buildPacket(brPacket.brMessageType.READY)
    
    def createCallbackPing(self):
        return self.buildPacket(brPacket.brMessageType.CALLBACK_PING)
