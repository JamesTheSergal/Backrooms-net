from dataclasses import dataclass, field
from .brPacket import brPacket
from ..brEnclave import Identity
import socket

@dataclass
class netconnection:
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
        difference = self.totalrequests - self.lastrequests
        self.lastrequests = self.totalrequests
        return difference
    
    def instatupdate(self):
        difference = self.bytesin - self.lastbytesin
        self.lastbytesin = self.bytesin
        return difference
    
    def outstatupdate(self):
        difference = self.bytesout - self.lastbytesout
        self.lastbytesout = self.bytesout
        return difference
    
    def receivePacket(self) -> brPacket:
        raw = self.soc.recv(1500)
        self.bytesin += len(raw)
        self.totalrequests += 1
        self.lastpacket = brPacket(raw)
        return self.lastpacket
    
    def send(self, packet:bytes):
        self.soc.sendall(packet)
        self.bytesout += len(packet)
        self.totalrequests += 1
    
    def sendReady(self):
        self.send(brPacket().createSimpleReady())
    
    def sendHello(self):
        self.send(brPacket().createSimpleHello())
        
    def sendPing(self):
        self.send(brPacket().createCallbackPing())
    
    def sendNodeInfo(self, message):
        self.send(brPacket().createNodeInfo(message))
        
    def close(self):
        self.soc.close()
        self.connected = False
        