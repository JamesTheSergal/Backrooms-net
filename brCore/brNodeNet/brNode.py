import threading
import time
import uuid

import requests
from dataclasses import dataclass, field

from . import brNodeCoreLog
logger = brNodeCoreLog

from brCore.brEnclave.Identity import Identity

@dataclass
class brNode:
    """
    A dataclass representing a peer node in the brNode network.

    Stores node connection details (IP, ports), state (latency, connected,
    handshake status), identity, friendly name, and timestamps for controller
    tracking and DHT announcements.
    """
    nodeIP: str
    nodePort: int = 13337
    webPort: int = 11000
    dhtport: int = 0
    
    # State
    lastLatency: int = 0
    connected: bool = False
    finishedHandshake: bool = False
    finishedBasicHandshake: bool = False

    # Identity
    identity: Identity = None
    localNodeID: uuid.UUID = field(default_factory=uuid.uuid4)
    friendlyName: str = "Unknown"

    # For controller
    firstSeen: float = field(default_factory=time.time)
    lastSeen: float = field(default_factory=time.time)
    apartOfRoutes:list = field(default_factory=list)
    #recordThreadLock: threading.Lock = field(default_factory=threading.Lock) # Will be removed later. Pickle can't serialize


    
    def queryPubKey(self):
        """
        Queries the node's public key by sending an HTTP GET request to
        http://{nodeIP}:{webPort}/pubkey.

        Imports the response text as the public key into self.identity using
        Identity.newIdentFromPubImport if the request succeeds.

        Handles ConnectionRefusedError and other exceptions gracefully.

        Returns:
            bool: True if public key retrieved and imported successfully,
                False otherwise (no IP, connection issues, non-200 status).
        """
        if self.nodeIP:
            requestURL = f'http://{self.nodeIP}:{str(self.webPort)}/pubkey'
            logger.info(f"Requesting public key from {requestURL}")
            try:
                response = requests.get(url=requestURL)
            except ConnectionRefusedError:
                logger.error("Connection refused when connecting to get public key.")
                return False
            except:
                logger.exception("Python Requests exception when requesting public key...", exc_info=True)
                return False
            if response.status_code != 200:
                return False
            nodeident = Identity().newIdentFromPubImport(response.text)
            self.identity = nodeident
            logger.debug("Public key has been imported successfully.")
            return True
        else:
            logger.error("IP of node not set. Cannot get pubkey. (Check the code)")
            return False

    def identFromPubKey(self, pubkey: str):
        nodeidentity = Identity().newIdentFromPubImport(pubkey)
        self.identity = nodeidentity
    
    def setNodeDisconnectedState(self):
        """
        Sets the node into a disconnected state.

        Resets self.lastLatency to 0 and self.connected to False.

        Returns:
            self: Allows method chaining.
        """
        self.lastLatency = 0
        self.connected = False
        return self
    
    
    def setNodeUUID(self, newuuid:str):
        """
        Changes the local node ID to a new UUID value.

        Args:
            newuuid (uuid.UUID): The new UUID to assign to self.localNodeID.

        Note:
            Logs the ID change from old to new.
        """
        logger.info(f"Changing node id from {self.localNodeID} to {newuuid}")
        self.localNodeID = uuid.UUID(str(newuuid))
        
    
    def makeDHTAnnounceDict(self, controllerID):
        """
        Creates a key-value pair suitable for announcing this unconfirmed node
        in the DHT.

        Args:
            controllerID: Identifier of the controller (str or UUID) announcing
                        the node.

        Returns:
            tuple[str, dict]: (key, data)
                - key: f'{self.localNodeID}_node_unconfirmed_by_{controllerID}'
                - data: dict with nodeIP, nodePort, webPort, dhtport, friendlyName,
                        firstSeen, lastSeen.

        Note:
            Excludes state, identity, and localNodeID from data.
        """
        key = f'{self.localNodeID}_node_unconfirmed_by_{controllerID}'
        data = {'nodeIP': self.nodeIP,
                'nodePort': self.nodePort,
                'webPort': self.webPort,
                'dhtport': self.dhtport,
                'friendlyName': self.friendlyName,
                'firstSeen': self.firstSeen,
                'lastSeen': self.lastSeen}
        return (key, data)
    
    def addApartOfRoute(self, route):
        if route not in self.apartOfRoutes:
            self.apartOfRoutes.append(route)
    
    def removeApartOfRoute(self, route):
        if route in self.apartOfRoutes:
            self.apartOfRoutes.pop(route)