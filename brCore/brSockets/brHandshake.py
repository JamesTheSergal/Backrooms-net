from enum import IntEnum
import pprint
from queue import Queue, Empty
import time

from .brPacket import brPacket
from .brNetwork import brRoute

class brControllerRequest:
    
    class requestType(IntEnum):
        REQUEST_CONFIG_DICT = 0
        PARSE_RECEIVED_CONFIG = 1
        PUBLIC_KEY_CHECK = 2
        COMPLETE_BASIC_HANDSHAKE = 3
    
    def __init__(self, controllerRequest:requestType, routeInfo:brRoute=None, data=None):
        self.requesttype = controllerRequest
        self.data = data
        self.routeInfo = routeInfo
        self.response = None
        self.done = False
        
    def waitForRequestComplete(self):
        while not self.done:
            time.sleep(1)
    
    def completeRequest(self, response):
        self.response = response
        self.done = True

class brHandshake:
    
    class handshakeException(Exception):
        """Base handshake exception class"""
        
    class badHello(handshakeException):
        """Exception raised when we receive bad data from a legacy hello"""

        def __init__(self, data) -> None:
            self.message = "Bad first hello packet (Data Involved) ->"
            self.data = data
            super().__init__(self.message, self.data)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"

    class handshakeResult:

        def __init__(self, error:bool, additionalInfo:str, rawData):
            self.error = error
            self.additionalInfo = additionalInfo
            self.rawData = rawData
            self.response = None

    class handshakeStep:
        
        def initiateHello(inputdata:brPacket=None):
            return brPacket().createSimpleHello()


        # If initiating the connection, Legacyhello creates a packet.
        # If we are on the receiving side, function will return a handshake result object
        def validateHello(inputdata:brPacket=None):

            # Validate
            if inputdata.messageType is brPacket.brMessageType.INTRODUCE:
                return brHandshake.handshakeResult(False,"",None)
            else:
                return brHandshake.handshakeResult(True,"brPacket did not have message type set to INTRODUCE.",inputdata)
        
        def transitionToReady(inputdata:brPacket=None):
            
            # Check for input data.
            if inputdata is None:
                return brPacket().createSimpleReady()
            else:
                # Validate
                if inputdata.messageType is brPacket.brMessageType.READY:
                    return brHandshake.handshakeResult(False,"",None)
                else:
                    return brHandshake.handshakeResult(True,"brPacket did not have message type set to READY.",inputdata)
        
        def sendConfig(inputdata=None):
            # Check for input data.
            if inputdata is None:
                return brControllerRequest(brControllerRequest.requestType.REQUEST_CONFIG_DICT)
            else:
                # Validate
                if type(inputdata) is brControllerRequest:
                    if inputdata.response is not None and type(inputdata.response) is brPacket:
                        return inputdata.response
                    else:
                        return brHandshake.handshakeResult(True,"Data returned back was either None or is not a brPacket",inputdata)
                else:
                    return brHandshake.handshakeResult(True,"Data was expected back from the controller request",inputdata)

        def receiveConfig(inputdata=None):
            
            if inputdata is None:
                return brHandshake.handshakeResult(True,"Got no data from receive config step.",inputdata)
            else:
                return brControllerRequest(brControllerRequest.requestType.PARSE_RECEIVED_CONFIG, data=inputdata)
            
        def completeBasicHandshake(inputdata=None):
            
            if inputdata is None:
                return brHandshake.handshakeResult(True,"Got no ready step back",inputdata)
            else:
                if inputdata.messageType is brPacket.brMessageType.READY:
                    return brControllerRequest(brControllerRequest.requestType.COMPLETE_BASIC_HANDSHAKE, data=inputdata)
            
                

    def brReceiveBasicHandshake():
        sequence = Queue(5)
        sequence.put(lambda inputdata=None: brHandshake.handshakeStep.validateHello(inputdata))
        sequence.put(lambda inputdata=None: brHandshake.handshakeStep.transitionToReady(inputdata))
        sequence.put(lambda inputdata=None: brHandshake.handshakeStep.receiveConfig(inputdata))
        sequence.put(lambda inputdata=None: brHandshake.handshakeStep.completeBasicHandshake(inputdata))
        
        
 
        return sequence
    
    def brInitiateBasicHandshake():
        sequence = Queue(5)
        sequence.put(lambda inputdata=None: brHandshake.handshakeStep.initiateHello(inputdata))
        sequence.put(lambda inputdata=None: brHandshake.handshakeStep.transitionToReady(inputdata))
        sequence.put(lambda inputdata=None: brHandshake.handshakeStep.sendConfig(inputdata))
        sequence.put(lambda inputdata=None: brHandshake.handshakeStep.completeBasicHandshake(inputdata))
 
        return sequence
    
    
