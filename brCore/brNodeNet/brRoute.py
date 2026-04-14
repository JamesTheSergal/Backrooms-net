from enum import IntEnum
from queue import Queue
import random
import socket
import threading
import time
import uuid
from . import brNodeCoreLog
from ..brSockets.brNodeRecord import brNodeRecord
from ..brSockets.brPacket import brPacket
logger = brNodeCoreLog

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

    def __init__(self, routeType:brRouteType, assignedConnection:socket.socket, externalNode:brNodeRecord, connectionType:brConnectionDirection):
        
        # Route Info
        self.routeID = uuid.uuid4()
        self.routeType = routeType 
        self.routeSecret = random.randrange(0, 1000000)
        # If we are a hop, we won't know these
        self.connectingFrom = None # Client on our end we are connecting
        self.connectingTo = None # Would be the client specifically we created this route for
        
        # Physical connection
        self.connectionType = connectionType
        self.assignedConn:socket.socket = assignedConnection # Our thread or some such
        self.connThread: threading.Thread = None
        
        # External Node info
        self.externalNode:brNodeRecord = externalNode # Would be the node Record 
        
        # Locks
        self.routeThreadLock = threading.Lock()
        
        # Controller
        self.timeToLive = 0
        self.controllerLastSeen = 0
        self.encryptionUpgraded = False
        self.mostRecentPacket:brPacket = None
        self.routerAction = False
        self.connectionFailed = False

        # Connection updates
        self.newNews = False
        self.news = Queue(maxsize=1000)
        self.newIncoming = False
        self.inbox = Queue(maxsize=1000)
        self.newOutgoing = False
        self.outbox = Queue(maxsize=1000)
        self.routeState = "Unknown"

        # Make reference to this route in the third party record
        with self.externalNode.recordThreadLock:
            self.externalNode.participatingInRoutes.append(self)

    def routerActionConfirmation(self):
        if self.routerAction:
            with self.routeThreadLock:
                self.routerAction = False
            return True
        else:
            return False
        
    def routerPerformedAction(self):
        with self.routeThreadLock:
            self.routerAction = True
    
    def isHandShakeComplete(self):
        return self.externalNode.finishedHandshake
    
    def setHandShakeComplete(self):
        logger.debug(f'Handshake with {self.externalNode.nodeIP} complete.')
        with self.routeThreadLock:
            self.externalNode.finishedHandshake = True

    def setConnectedState(self, state:bool):
        with self.routeThreadLock:
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
        with self.routeThreadLock:
            self.routeState = "Idle"

    def setRouteStateBusy(self):
        with self.routeThreadLock:
            self.routeState = "Busy"

    def upgradeRouteType(self, brtype:brRouteType):
        with self.routeThreadLock:
            self.routeType = brtype
            self.controllerLastSeen = 0
    
    def controllerLastSeenNow(self):
        with self.routeThreadLock:
            self.controllerLastSeen = time.time()

    def removeRouteReference(self):
        with self.externalNode.recordThreadLock:
            self.externalNode.participatingInRoutes.remove(self)