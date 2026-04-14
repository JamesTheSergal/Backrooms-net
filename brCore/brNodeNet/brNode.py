import threading
import time
import uuid

import requests

from .brRoute import brRoute
from . import brNodeCoreLog
logger = brNodeCoreLog

from brCore.brEnclave.Identity import Identity

class brNode:

    def __init__(self):
        # Node details
        self.nodeIP:str = None
        self.nodePort:int = 443
        self.webPort:int = 80
        self.dhtport:int = None
        
        # State
        self.lastLatency = 0
        self.connected = False
        self.finishedUnencryptedHandshake = False
        self.finishedHandshake = False

        # Identity
        self.identity:Identity = None
        self.localNodeID = uuid.uuid4()
        self.friendlyName = "Unknown"

        # For controller
        self.firstSeen = time.time()
        self.lastSeen = 0
        self.recordThreadLock = threading.Lock()
        self.participatingInRoutes:list[brRoute] = []

        logger.info(f'New node record ID: {self.localNodeID}')

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
        
    def setNodeAddress(self, addressTupl:tuple):
        self.nodeIP = addressTupl[0]
        self.nodePort = addressTupl[1]

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