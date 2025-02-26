import socket
from core.Logging import loggingfactory
from core.brDataBuilder import brPacket

logger = loggingfactory.createNewLogger("brNodeNetwork")

class commonNetworkFunctions:

    def receiveAndDecompile(connection:socket.socket):
        try:
            packet = connection.recv(1024)
            return brPacket.decompile(packet)
        except Exception:
            logger.exception("")

    def sendIntroAndWait(connection:socket.socket):
        # Send intro packet
        tosend = brPacket.createIntroPacket()
        packet = tosend.buildPacket()
        try:
            connection.sendall(packet)
        except Exception as e:
            return False
        return True

class alpha0001_handshake:
    
    def __init__(self, connection):
        self.completed = False
        self.connection = connection

    def handshake(self, outgoing:bool):
        if outgoing:
            self.initiate()
        else:
            self.receive()

    def initiate(self):
        commonNetworkFunctions.sendIntroAndWait(self.connection)
        
        
    def receive(self):
        packet = commonNetworkFunctions.receiveAndDecompile(self.connection)

