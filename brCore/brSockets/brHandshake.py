from enum import IntEnum
import pprint
from queue import Queue, Empty
import time

from . import brNodeHsLog as logger
from .brPacket import brPacket
from .brNetwork import brRoute
from ..brSockets.netconnection import netconnection
        
class brBasicHandshake:
    
    def __init__(self, connection:netconnection):
        self.con = connection
        
    def validateHello(self,packet:brPacket):
        if packet.messageType is brPacket.brMessageType.INTRODUCE:
            return True
        else:
            return False
    
    def validateReady(self,packet:brPacket):
        if packet.messageType is brPacket.brMessageType.READY:
            return True
        else:
            return False
        
    def validateNodeInfo(self,packet:brPacket):
        if packet.messageType is brPacket.brMessageType.NODE_INFO:
            return True
        else:
            return False
    
    def initiate(self, nodeConfig):
        logger.info(f"Initiating handshake on: {self.con.ip}:{self.con.port}")
        self.con.sendHello()
        packet = self.con.receivePacket()
        self.validateHello(packet)
        packet = self.con.receivePacket()
        self.validateReady(packet)
        self.con.sendNodeInfo(nodeConfig)
        packet = self.con.receivePacket()
        self.validateReady(packet)
        self.con.sendReady()
        
        logger.info("Initiated handshake was successful.")
        
        
    def receive(self):
        logger.info(f'Receiving handshake from {self.con.ip}:{self.con.port}')
        packet = self.con.receivePacket()
        self.validateHello(packet)
        self.con.sendHello()
        self.con.sendReady()
        packet = self.con.receivePacket()
        self.validateNodeInfo(packet)
        nodeInfo = packet.rebuildObject()
        self.con.sendReady()
        packet = self.con.receivePacket()
        self.validateReady(packet)
        
        logger.info("Received handshake was successful.")
        self.con.sendPing()
        return nodeInfo
