import socket
from .brHandshake import Handshake
from brCore import BR_VERSION
from brCore.brSockets.brPacket import brPacket
from brCore import brNodeHsLog as debuglog

class brDebugHandshake(Handshake):
    
    def __init__(self, target_socket: socket.socket=None, initiateHandshake=True):
        super().__init__(target_socket, initiateHandshake) 
        
    def _handshake_step_exec(self):
        match self.handShakeStep:
            case 1:
                if self.initiateHandshake:
                    debuglog.info("Initiating handshake...")
                    self._send_response(brPacket().createSimpleHello())
                else:
                    debuglog.debug("Waiting for peer to send introduction...")
                    self.expected_response = brPacket().createSimpleHello()
                    rawData = self._receive_response()
                    brReturn = brPacket(rawData)
                    
                    if rawData != self.expected_response:
                        if brReturn.version != BR_VERSION:
                            debuglog.warning(f"Backrooms version mismatch! Peer: {brReturn.version} Us: {BR_VERSION}")
                            self.success = False
                        else:
                            debuglog.error("Malformed response from peer, closing connection.")
                            self.success = False
                    else:
                        debuglog.info("Got intro packet.")
                        self.success = True
            case 2:
                if self.initiateHandshake:
                    debuglog.info("Serve agent finished handshake")
                    self.success = True
            case _:
                debuglog.error("Step counter out of bounds. Handshake failed.")
                self.success = False