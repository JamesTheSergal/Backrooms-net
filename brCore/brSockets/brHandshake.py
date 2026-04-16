from enum import IntEnum
import pprint
from queue import Queue, Empty
import time

from . import brNodeHsLog as logger
from .brPacket import brPacket
from .brNetwork import brRoute
from ..brSockets.netconnection import netconnection
        
class brBasicHandshake:
    """
    Implements the basic handshake protocol for brNode connections.

    This class manages the exchange of hello, node info, and ready messages
    to establish a connection between two nodes using a netconnection.
    Supports both client-side (initiate) and server-side (receive) roles.
    """
    
    def __init__(self, connection:netconnection):
        """
        Initialize the handshake handler.

        Args:
            connection (netconnection): The underlying network connection.
        """
        self.con = connection
        
    def validateHello(self,packet:brPacket):
        """
        Validate that the packet is a HELLO message (INTRODUCE type).

        Args:
            packet (brPacket): The received packet.

        Returns:
            bool: True if messageType is INTRODUCE, else False.
        """
        if packet.messageType is brPacket.brMessageType.INTRODUCE:
            return True
        else:
            return False
    
    def validateReady(self,packet:brPacket):
        """
        Validate that the packet is a READY message.

        Args:
            packet (brPacket): The received packet.

        Returns:
            bool: True if messageType is READY, else False.
        """
        if packet.messageType is brPacket.brMessageType.READY:
            return True
        else:
            return False
        
    def validateNodeInfo(self,packet:brPacket):
        """
        Validate that the packet is a NODE_INFO message.

        Args:
            packet (brPacket): The received packet.

        Returns:
            bool: True if messageType is NODE_INFO, else False.
        """
        if packet.messageType is brPacket.brMessageType.NODE_INFO:
            return True
        else:
            return False
    
    def initiate(self, nodeConfig):
        """
        Perform the client-side handshake initiation.

        Sequence:
        1. Send HELLO
        2. Receive HELLO (INTRODUCE)
        3. Receive READY
        4. Send NODE_INFO (with nodeConfig)
        5. Receive READY
        6. Send READY

        Args:
            nodeConfig: The local node's configuration data to send.
        """
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
        """
        Perform the server-side handshake reception.

        Sequence:
        1. Receive HELLO (INTRODUCE)
        2. Send HELLO
        3. Send READY
        4. Receive NODE_INFO
        5. Send READY
        6. Receive READY
        7. Send PING

        Returns:
            The remote node's info object rebuilt from NODE_INFO packet.
        """
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
