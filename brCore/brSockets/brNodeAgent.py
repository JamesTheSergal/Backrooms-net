import socket

from . import brAgentLog
from brCore.brSockets.brProtocols.brInsecureHandshake import brDebugHandshake
from brCore.brSockets.brPacket import brPacket

class brSocketAgent:
    def __init__(self, con_addr, port, listen:bool=False, handoffSocket:socket.socket=None, autoRecoverDelay:int=0, retries=4):
        if listen:
            try:
                self.socCon = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socCon.bind((con_addr, port))
                self.socCon.listen(4)
            except Exception as e:
                brAgentLog.exception("Failed to open a socket to listen!", exc_info=True)
        else:
            self.socCon = handoffSocket
            
            if self.socCon is not None:
                self.con_addr, self.port = self.socCon.getpeername()
                self.handshake = brDebugHandshake(self.socCon)
            else:
                self.con_addr = con_addr
                self.port = port
            
            
            self.autoRecoverDelay = autoRecoverDelay
            self.retries = retries
            
            # State of connection
            #self.isConnected
            #self.heartBeatComplete
        
    def connect(self):
        """
        Establish connection to specified address
        """
        
        if self.socCon is None:
            try:
                brAgentLog.debug("Creating socket object...")
                self.socCon = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                brAgentLog.info(f"Connecting to {self.con_addr}")
                self.socCon.connect((self.con_addr, self.port))
                brAgentLog.info(f"Connection to {self.con_addr} was successful.")
            except Exception as e:
                brAgentLog.exception(f"Failed to connect to host.", exc_info=True)
                
            try:
                brAgentLog.info(f"Performing handshake with {self.con_addr}")
                self.handshake = brDebugHandshake(self.socCon, initiateHandshake=False)
                self.handshake.perform()
            except Exception as e:
                brAgentLog.exception("Handshake failed to complete.", exc_info=True)
                
        else:
            brAgentLog.info("Socket was handed off, assuming that the initial connection is complete.")
            try:
                brAgentLog.info(f"Performing handshake with {self.con_addr}")
                self.handshake = brDebugHandshake(self.socCon, initiateHandshake=False)
                self.handshake.perform()
            except Exception as e:
                brAgentLog.exception("Handshake failed to complete.", exc_info=True)
                
        brAgentLog.info(f"Connection with {self.con_addr} is complete. Ready to start sending data.")
    
    def serveAgent(self, serveSoc):
        brAgentLog.info("Accepted connection - performing handshake...")
        try:
            serveHandshake = brDebugHandshake(serveSoc, initiateHandshake=True)
            serveHandshake.perform()
        except Exception as e:
            brAgentLog.exception("Failed to negotiage a handshake with the client!", exc_info=True)
            return
        
        brAgentLog.info("Successfully negotiated with client.")
    
    def serve(self):
        """
        Serves a connection to the agent
        """
        
        brAgentLog.info("Serving the agent...")
        
        while True:
            try:
                connectionSoc, peer_address = self.socCon.accept()
            except Exception as e:
                brAgentLog.exception("Error occured when creating socket!", exc_info=True)
                return
            
            self.serveAgent(connectionSoc)
        
    def receive_data(self):
        """
        Receives raw data from the peer
        """
        if not self.socCon or not self.socCon.fileno():
            raise Exception("Socket not connected. Call connect() first.")
        
        try:
            return self.socCon.recv(1024)
        except Exception as e:
            brAgentLog.exception(f"Sending data failed...", exc_info=True)
    
    def receive_brPacket(self):
        if not self.socCon or not self.socCon.fileno():
            raise Exception("Socket not connected. Call connect() first.")
        
        try:
            rawdata = self.socCon.recv(1024)
        except Exception as e:
            brAgentLog.exception(f"Sending data failed...", exc_info=True)
            
        return brPacket(rawdata)
    
    def send_data(self, data: bytes):
        
        brAgentLog.debug(f"Sending {len(data)} raw bytes to {self.con_addr}")
        
        if not self.socCon or not self.socCon.fileno():
            raise Exception("Socket not connected. Call connect() first.")
        self.socCon.sendall(data.encode())
        
    def send_brPacket(self, data: bytes):
        
        brAgentLog.debug(f"Sending {len(data)} bytes as brPacket to {self.con_addr}")
        
        if not self.socCon or not self.socCon.fileno():
            raise Exception("Socket not connected. Call connect() first.")
        
        pending = brPacket()
        pending.data = data
        pending.setMessageType(brPacket.brMessageType.MESSAGE)
        packet = pending.buildPacket()
        self.socCon.sendall(packet)
        
    def start(self):
        pass
        