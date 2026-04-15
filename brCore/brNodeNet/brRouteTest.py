from enum import IntEnum
from queue import Queue
import random
import socket
import threading
import time
import uuid
from . import brNodeCoreLog
from . import brNode
from ..brSockets.brPacket import brPacket
logger = brNodeCoreLog

from dataclasses import dataclass, field

class brRouteType(IntEnum):
    CONTROL = 0
    TEST = 1
    UNENCRYPTED = 2
    ENCRYPTED = 3
    ONION = 4
    HIGHWAY = 5
        
class brConnectionDirection(IntEnum):
    INITIATED = 0
    RECEIVED = 1

@dataclass
class brRoute:
    routeID: uuid.UUID = field(default_factory=uuid.uuid4)
    routeType: int = 1
    routeSecret: int = field(default_factory=lambda: random.range(0,1000000))