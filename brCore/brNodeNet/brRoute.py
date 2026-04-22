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
    """
    A dataclass representing a route to an external node in the brNode network.

    Routes manage connections, message queues (news, inbox, outbox), encryption upgrades,
    state tracking, and TTL. Supports various route types like control, encrypted, onion.
    Designed for pickling, excluding live sockets and queues which are recreated.
    """
    class brRouteType(IntEnum):
        """
        Enumeration of supported route types, defining purpose and security level.

        Attributes:
            CONTROL (0): Management and control traffic.
            TEST (1): Testing and diagnostic connections.
            UNENCRYPTED (2): Plaintext data transfer (low security).
            ENCRYPTED (3): End-to-end encrypted direct connection.
            ONION (4): Privacy-focused onion routing.
            HIGHWAY (5): High-throughput optimized route.
        """
        CONTROL = 0
        TEST = 1
        UNENCRYPTED = 2
        ENCRYPTED = 3
        ONION = 4
        HIGHWAY = 5
        
    class brConnectionDirection(IntEnum):
        """
        Direction in which the connection was established.

        Attributes:
            INITIATED (0): This node initiated the outgoing connection.
            RECEIVED (1): Incoming connection accepted from peer.
        """
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
        """
        Confirm and clear the router action flag.

        Used by the route controller to check if the router node has performed
        a requested action (e.g., forwarding setup).

        Returns:
            bool: True if a pending action was confirmed and cleared, else False.
        """
        if self.routerAction:
            self.routerAction = False
            return True
        else:
            return False
        
    def routerPerformedAction(self):
        """
        Signal that the router has completed a requested action.

        Sets the routerAction flag for the controller to poll.
        """
        self.routerAction = True
    
    def isHandShakeComplete(self):
        """
        Check if the initial handshake with the external node is complete.

        Returns:
            bool: True if handshake finished.
        """
        return self.externalNode.finishedHandshake
    
    def setHandShakeComplete(self):
        """
        Mark the handshake as complete and log the event.
        """
        logger.debug(f'Handshake with {self.externalNode.nodeIP} complete.')
        self.externalNode.finishedHandshake = True
        
    def setBasicHandShakeComplete(self):
        """
        Mark the handshake as complete and log the event.
        """
        logger.debug(f'Basic handshake with {self.externalNode.nodeIP} complete.')
        self.externalNode.finishedBasicHandshake = True

    def setConnectedState(self, state: bool):
        """
        Update the connection state of the external node.

        Args:
            state (bool): New connection status (True if connected).
        """
        self.externalNode.connected = state

    def externalPubKeyCheck(self):
        """
        Verify availability of the external node's public key.
        Queries if missing.

        Returns:
            bool: True if public key is available.
        """
        # Just make sure we have the other parties Public key.
        if self.externalNode.identity == None:
            if self.externalNode.queryPubKey():
                return True
            else:
                return False
        else:
            return True
                
    def setRouteStateIdle(self):
        """
        Set the route state to idle.
        """
        self.routeState = "Idle"

    def setRouteStateBusy(self):
        """
        Set the route state to busy.
        """
        self.routeState = "Busy"

    def upgradeRouteType(self, brtype: brRouteType):
        """
        Upgrade the route to a higher security or different type,
        resetting controller last seen timer.

        Args:
            brtype (brRouteType): New route type.
        """
        self.routeType = brtype
        self.controllerLastSeen = time.time()
    
    def controllerLastSeenNow(self):
        """
        Update the timestamp of last controller interaction.
        """
        self.controllerLastSeen = time.time()

    def removeRouteReference(self):
        """
        Remove this route instance from the external node's list of participating routes.
        """
        self.externalNode.participatingInRoutes.remove(self)
            
    def makeDHTAnnounceDict(self, controllerID):
        """
        Prepare a key-value pair for announcing the route in DHT.

        Args:
            controllerID: Identifier of the route controller (currently unused).

        Returns:
            tuple[str, dict]: (DHT key, route data dictionary).
        """
        key = f'{self.routeID}_route'
        data = {'routeType': self.routeType,
                'connectingFrom': self.connectingFrom,
                'connectingTo': self.connectingTo,
                'externalNode': self.externalNode.localNodeID,
                'timeToLive': self.timeToLive,
                'routeState': self.routeState}
        return (key, data)
    
    def setRouteSecret(self, secret:int):
        logger.info(f'Setting route secret for {self.routeID} - both nodes should match')
        self.routeSecret = secret
        
    def setRouteType(self, newType:brRouteType):
        logger.info(f'Route {self.routeID} upgraded to {self.routeType.name}')
    
    def __getstate__(self):
        """
        Custom __getstate__ for pickling.

        Excludes non-serializable fields: assignedConn (socket), news/inbox/outbox queues.

        Returns:
            dict: Serializable state dictionary.
        """
        state = self.__dict__.copy()
        # Exclude assignedConn to prevent pickling the socket
        state.pop('assignedConn', None)
        state.pop('news', None)
        state.pop('inbox', None)
        state.pop('outbox', None)
        return state
    
    def __setstate__(self, state):
        """
        Custom __setstate__ for unpickling.

        Recreates queues and resets assignedConn to None (reconnect required).
        """
        self.__dict__.update(state)
        # Set assignedConn to None after unpickling (connection must be re-established)
        self.assignedConn = None
        self.news = Queue(maxsize=1000)
        self.inbox = Queue(maxsize=1000)
        self.outbox = Queue(maxsize=1000)