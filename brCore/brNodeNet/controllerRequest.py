from dataclasses import dataclass, field
from enum import IntEnum
from .brNode import brNode

@dataclass
class brControllerRequest:
    
    class requestType(IntEnum):
        SUBMIT_KNOWN_NODE = 0
    
    controllerRequestType: requestType
    node:brNode = None
