from enum import IntEnum
import pickle
import pprint

from . import BR_VERSION


class brPacket:
    """brPacket - Core class for Backrooms Protocol packet handling.

    Manages parsing raw network packets, validating protocol compliance,
    building packets for transmission, and serializing/deserializing payloads
    using Python's pickle module.

    **Packet Format (17-byte header + data):**
    - Byte 0: messageType (brMessageType enum, 1 byte)
    - Bytes 1-14: version (null-padded UTF-8 string, 14 bytes)
    - Bytes 15-16: contentLength (uint16 big-endian, 2 bytes)
    - Bytes 17+: data (pickled object, ≤1483 bytes)

    Raises backroomsProtocolException subclasses on violations.
    """
    MAX_DATA_BYTES = 1483
    VALID_VERSIONS = ["0.0.1-alpha"]

    class backroomsProtocolException(Exception):
        """Base exception raised for Backrooms Protocol violations."""
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
        """Enumeration defining valid message types for brPacket."""
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
        FRIEND_ANNOUNCE = 8  # Used to tell other nodes around us who our friends are
        PING = 9
        CALLBACK_PING = 10   # Absolute Solver - Used to provide a window for response
        UR_BEHIND_NAT = 11  # Message type to send when we think a remote node is behind a NAT.
        NEWS = 12           # News is between controllers for things like disconnections / network events

        # Message Handling
        NEW_MESSAGE = 13    # Packet will contain the number of packets after this one to be received
        READY_MESSAGE = 14  # Response that we are ready to receive sequence
        MESSAGE = 15        # Data to receive
        
        
   
    def __init__(self, receivedPacket:bytes=None) -> None:
        """Initialize packet from raw bytes or as builder.

        Args:
            receivedPacket (bytes, optional): Raw packet bytes to parse/validate.
                If None, creates empty packet for outbound construction.

        Raises:
            brInvalidMessageType: Invalid message type byte.
            brInvalidVersion: Malformed or unsupported version.
            brInvalidContentLength: Invalid length field or oversized.
        """

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
        """Convert instance fields to serialized bytes for packet building.

        Updates self.messageType (1 byte), self.version (14 bytes padded),
        self.contentLength (2 bytes big-endian) in-place.

        Raises:
            brInvalidMessageType: If messageType unset.
        """
        if self.messageType is None:
            raise self.brInvalidMessageType("Message type was not specified.")
        
        self.messageType = self.messageType.to_bytes(1)
        self.contentLength = self.contentLength.to_bytes(2)
        self.version = self.version.encode("utf-8").ljust(14, b'\0')


    
    def setMessageType(self, msgdesc:int):
        """Set the packet message type.

        Args:
            msgdesc (int): Numeric value from brMessageType.

        Returns:
            brPacket: self (chainable).
        """
        if msgdesc in brPacket.brMessageType:
            self.messageType = msgdesc
            return self
        else:
            pass # Raise exception 
        
    
    def insertObject(self, insertdata:any):
        """Serialize object into packet data via pickle.

        Args:
            insertdata (Any): Arbitrary Python object to store as payload.

        Returns:
            brPacket: self (chainable).

        Raises:
            brPacketOversize: Pickled data exceeds MAX_DATA_BYTES (1483).
        """
        objdata = pickle.dumps(insertdata)
        if len(objdata) <= self.MAX_DATA_BYTES:
            self.contentLength = len(objdata)
            self.data = objdata
        else:
            raise self.brPacketOversize()
        return self
        
    
    def rebuildObject(self):
        """Deserialize packet data back to Python object.

        Returns:
            Any: Original object from pickle.loads(self.data).

        Note:
            No validation; may raise pickle.UnpicklingError.
        """
        objdata = pickle.loads(self.data)
        return objdata

    
    def buildPacket(self, msgType:brMessageType=None) -> bytes:
        """Assemble complete packet bytes from fields.

        Args:
            msgType (brMessageType, optional): Set message type if unset.

        Returns:
            bytes: Validated packet bytes (header + data).

        Raises:
            brInvalidMessageType: Message type invalid/missing.
            brPreFlightCheckFailure: Header != 17 bytes.
        """

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
        """Build empty INTRODUCE packet for initial connection.

        Returns:
            bytes: Ready-to-send packet.
        """
        return self.buildPacket(brPacket.brMessageType.INTRODUCE)
    
    
    def createSimpleReady(self):
        """Build empty READY packet to acknowledge handshake.

        Returns:
            bytes: Ready-to-send packet.
        """
        return self.buildPacket(brPacket.brMessageType.READY)
    
    
    def createCallbackPing(self):
        """Build empty CALLBACK_PING packet for latency/response window.

        Returns:
            bytes: Ready-to-send packet.
        """
        return self.buildPacket(brPacket.brMessageType.CALLBACK_PING)
    
    
    def createNodeInfo(self, message):
        """Build NODE_INFO packet with pickled node details.

        Args:
            message (Any): Node information object.

        Returns:
            bytes: Ready-to-send packet.
        """
        return self.insertObject(message).buildPacket(brPacket.brMessageType.NODE_INFO)
