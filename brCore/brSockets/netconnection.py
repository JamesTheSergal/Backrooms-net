from dataclasses import dataclass, field
from .brPacket import brPacket
from ..brEnclave import Identity
from . import brNodeCoreLog as logger
import socket

@dataclass
class netconnection:
    """Dataclass representing a network connection to a remote Backrooms Protocol node.

    Manages socket I/O, protocol packet send/receive, connection statistics,
    and encryption state.

    Attributes:
        soc (socket.socket): The underlying TCP socket.
        ip (str): IP address of the remote peer.
        port (int): Port number of the remote peer.
        connected (bool): Flag indicating if the connection is active.
        encryptionident (Identity): Encryption identity from brEnclave.
        usingencryption (bool): Whether encryption is currently in use. Default False.
        totalrequests (int): Total packets sent/received. Default 0.
        bytesin (int): Total bytes received. Default 0.
        bytesout (int): Total bytes sent. Default 0.
        lastpacket (brPacket): The most recently received packet. Default None.
        lastrequests (int): totalrequests value at last stat update. Default 0.
        lastbytesin (int): bytesin value at last stat update. Default 0.
        lastbytesout (int): bytesout value at last stat update. Default 0.
    """ 
    soc: socket.socket
    ip: str
    port: int
    connected: bool
    encryptionident: Identity
    usingencryption: bool = False
    totalrequests: int = 0
    bytesin: int = 0
    bytesout: int = 0
    lastpacket: brPacket = None
    lastrequests: int = 0
    lastbytesin: int = 0
    lastbytesout: int = 0
    
    
    def requeststatupdate(self):
        """Calculates and returns the difference in total requests since the last update.

        Updates self.lastrequests to current self.totalrequests.

        Returns:
            int: Number of requests/packets since last call.
        """
        difference = self.totalrequests - self.lastrequests
        self.lastrequests = self.totalrequests
        return difference
    
    
    def instatupdate(self):
        """Calculates and returns the difference in bytes received since the last update.

        Updates self.lastbytesin to current self.bytesin.

        Returns:
            int: Bytes received since last call.
        """
        difference = self.bytesin - self.lastbytesin
        self.lastbytesin = self.bytesin
        return difference
    
    
    def outstatupdate(self):
        """Calculates and returns the difference in bytes sent since the last update.

        Updates self.lastbytesout to current self.bytesout.

        Returns:
            int: Bytes sent since last call.
        """
        difference = self.bytesout - self.lastbytesout
        self.lastbytesout = self.bytesout
        return difference
    
    
    def receivePacket(self) -> brPacket:
        """Receives a single brPacket from the socket.

        Performs recv(1500), updates bytesin and totalrequests stats,
        constructs brPacket from raw bytes, stores as self.lastpacket,
        and returns it.

        Note:
            Assumes packets fit in 1500 bytes; no handling for larger or partial reads.

        Returns:
            brPacket: The parsed and validated packet.
        """
        self.soc.settimeout(0.25)
        raw = self.soc.recv(1500)
        if len(raw) == 0:
            logger.warning(f"EOF from peer {self.ip}:{self.port} - connection closed")
            self.close()
            raise ConnectionError(f"Connection closed by peer {self.ip}:{self.port}")
        self.bytesin += len(raw)
        self.totalrequests += 1
        self.lastpacket = brPacket(raw)
        return self.lastpacket
    
    def send(self, packet:bytes):
        """Sends raw packet bytes over the socket.

        Uses socket.sendall for reliable transmission,
        updates bytesout and totalrequests stats.

        Args:
            packet (bytes): Raw packet bytes to transmit.
        """
        self.soc.sendall(packet)
        self.bytesout += len(packet)
        self.totalrequests += 1
    
    def sendReady(self):
        """Sends a simple READY packet (brMessageType.READY) to acknowledge handshake."""
        self.send(brPacket().createSimpleReady())
    
    def sendHello(self):
        """Sends a simple HELLO/INTRODUCE packet (brMessageType.INTRODUCE) for initial connection."""
        self.send(brPacket().createSimpleHello())
        
    def sendPing(self):
        """Sends a CALLBACK_PING packet (brMessageType.CALLBACK_PING) for latency/response testing."""
        self.send(brPacket().createCallbackPing())
    
    def sendNodeInfo(self, message):
        """Sends a NODE_INFO packet with pickled node information.

        Args:
            message (Any): Picklable object containing node details.
        """
        self.send(brPacket().createNodeInfo(message))
        
    def close(self):
        """Closes the socket and sets connected flag to False."""
        self.soc.close()
        self.connected = False
        