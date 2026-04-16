from dataclasses import dataclass, field
from enum import IntEnum
from queue import Queue
import random
import socket
import threading
import time
import uuid
from . import brNodeCoreLog
from ..brNodeNet.brNode import brNode
from ..brSockets.brPacket import brPacket
from ..brSockets.netconnection import netconnection
logger = brNodeCoreLog

@dataclass
class brRoute:
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

    # Fields
    routeType: brRouteType
    externalNode: brNode
    connectionType: brConnectionDirection
    assignedConn: netconnection = None
    routeID: uuid.UUID = field(default_factory=uuid.uuid4)
    routeSecret: int = field(default_factory=lambda: random.randrange(0, 1000000))
    connectingFrom: str = None
    connectingTo: str = None
    #routeThreadLock: threading.Lock = field(default_factory=threading.Lock) # Will be removed later. Pickle can't serialize
    timeToLive: int = 0
    controllerLastSeen: float = 0
    encryptionUpgraded: bool = False
    routerAction: bool = False
    connectionFailed: bool = False
    newNews: bool = False
    news: Queue = field(default_factory=lambda: Queue(maxsize=1000))
    newIncoming: bool = False
    inbox: Queue = field(default_factory=lambda: Queue(maxsize=1000))
    newOutgoing: bool = False
    outbox: Queue = field(default_factory=lambda: Queue(maxsize=1000))
    routeState: str = "Unknown"


    def routerActionConfirmation(self):
        if self.routerAction:
            self.routerAction = False
            return True
        else:
            return False
        
    def routerPerformedAction(self):
        self.routerAction = True
    
    def isHandShakeComplete(self):
        return self.externalNode.finishedHandshake
    
    def setHandShakeComplete(self):
        logger.debug(f'Handshake with {self.externalNode.nodeIP} complete.')
        self.externalNode.finishedHandshake = True

    def setConnectedState(self, state:bool):
        self.externalNode.connected = state

    def externalPubKeyCheck(self):
        # Just make sure we have the other parties Public key.
        if self.externalNode.identity == None:
            if self.externalNode.queryPubKey():
                return True
            else:
                return False
        else:
            return True
                
    def setRouteStateIdle(self):
        self.routeState = "Idle"

    def setRouteStateBusy(self):
        self.routeState = "Busy"

    def upgradeRouteType(self, brtype:brRouteType):
        self.routeType = brtype
        self.controllerLastSeen = 0
    
    def controllerLastSeenNow(self):
        self.controllerLastSeen = time.time()

    def removeRouteReference(self):
            self.externalNode.participatingInRoutes.remove(self)
            
    def makeDHTAnnounceDict(self, controllerID):
        key = f'{self.routeID}_route'
        data = {'routeType': self.routeType,
                'connectingFrom': self.connectingFrom,
                'connectingTo': self.connectingTo,
                'externalNode': self.externalNode.localNodeID,
                'timeToLive': self.timeToLive,
                'routeState': self.routeState}
        return (key, data)
    
    def __getstate__(self):
        state = self.__dict__.copy()
        # Exclude assignedConn to prevent pickling the socket
        state.pop('assignedConn', None)
        state.pop('news', None)
        state.pop('inbox', None)
        state.pop('outbox', None)
        return state
    
    def __setstate__(self, state):
        self.__dict__.update(state)
        # Set assignedConn to None after unpickling (connection must be re-established)
        self.assignedConn = None
        self.news = Queue(maxsize=1000)
        self.inbox = Queue(maxsize=1000)
        self.outbox = Queue(maxsize=1000)