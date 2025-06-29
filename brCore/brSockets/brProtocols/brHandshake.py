import socket
from .. import BR_VERSION
from .. import brNodeHsLog

class Handshake:
    """
    Abstract base class for different types of handshakes.
    This defines what a handshake can do to a socket
    """
    
    class HandshakeException(Exception):
        pass
    
    def __init__(self, target_socket: socket.socket=None, initiateHandshake=True):
        # Core data
        self.soc = target_socket
        self.soc_addr, self.soc_port = self.soc.getpeername()
        
        # key variables in the base handshake
        self.expected_response = None
        self.lastData = None
        self.initiateHandshake = initiateHandshake
        
        # States
        self.success = None # Will become True or False
        self.handShakeStep = 1
        
    def perform(self):
        """
        Perform the handshake steps 
        """
        
        brNodeHsLog.info(f'Initiating a handshake with {self.soc_addr}...')
        
        while self.success is None:
            brNodeHsLog.debug(f"Performing handshake step {self.handShakeStep}...")
            self._handshake_step_exec()
            self.handShakeStep = self.handShakeStep+1
            
        if self.success:
            brNodeHsLog.info(f"Finished handshake with {self.soc.getpeername()}")
        else:
            brNodeHsLog.error(f"Handshake with {self.soc.getpeername()} failed.\nExpected response: {self.expected_response}\nGot Data: {self.lastData}")
            raise Handshake.HandshakeException()
    
    def _handshake_step_exec(self):
        """
        The subclass will implement this to return handshake
        """
        raise NotImplementedError("Subclass must implement this method")
    
    def _update_expected_response(self, expectation):
        brNodeHsLog.debug(f"Set new expected response to: {expectation}")
        self.expected_response = expectation
        self.handShakeStep = self.handShakeStep+1
        
    def _receive_response(self):
        self.lastData = self.soc.recv(1024)
        return self.lastData
    
    def _send_response(self, data):
        return self.soc.sendall(data)
    