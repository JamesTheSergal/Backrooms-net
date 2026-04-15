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
        self.send(brPacket().createSimpleReady())
        
    def sendPing(self):
        self.send(brPacket().createSimpleReady())
        
    def close(self):
        self.soc.close()
        self.connected = False
        