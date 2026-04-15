import threading
import time
import uuid

import requests
from dataclasses import dataclass, field

from .brRoute import brRoute
from . import brNodeCoreLog
logger = brNodeCoreLog

from brCore.brEnclave.Identity import Identity

@dataclass
class brNode:

    # Node details
    nodeIP: str
    nodePort: int = 13337
    webPort: int = 11000
    dhtport: int = 23338
    
    # State
    lastLatency: int = 0
    connected: bool = False
    finishedUnencryptedHandshake: bool = False
    finishedHandshake: bool = False

    # Identity
    identity: Identity = None
    localNodeID: uuid.UUID = field(default_factory=uuid.uuid4)
    friendlyName: str = "Unknown"

    # For controller
    firstSeen: float = field(default_factory=time.time)
    lastSeen: float = 0
    recordThreadLock: threading.Lock = field(default_factory=threading.Lock)


    def queryPubKey(self):
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

    def setNodeDisconnectedState(self):
        with self.recordThreadLock:
            self.lastLatency = 0
            self.connected = False
            self.participatingInRoutes.clear()
            # Pickle cannot store thread locks, so we must make it none!
            self.recordThreadLock = None
        return self
    
    def setNodeUUID(self, newuuid):
        logger.info(f"Changing node id from {self.localNodeID} to {newuuid}")
        self.localNodeID = newuuid
        
    def makeDHTAnnounceDict(self, controllerID):
        key = f'{self.localNodeID}_node_unconfirmed_by_{controllerID}'
        data = {'nodeIP': self.nodeIP,
                'nodePort': self.nodePort,
                'webPort': self.webPort,
                'dhtport': self.dhtport,
                'friendlyName': self.friendlyName,
                'firstSeen': self.firstSeen,
                'lastSeen': self.lastSeen}
        return (key, data)