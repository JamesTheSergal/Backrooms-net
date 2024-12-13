from enum import IntEnum
import random
import socket
import threading
import time
import uuid

import requests
from core import loggingfactory, notrustvars

logger = loggingfactory.createNewLogger("brNodeNetwork")

class brNode():
    
    def __init__(self, nodeIP:str, nodePort:int) -> None:
        
        # Net Records
        self.nodeIP:str = None
        self.nodePort:int = 443
        self.webPort:int = 80
        self.controlConnection:brRoute = None
        self.lastLatency = 0
        self.connected = False
        self.completedHandshake = False
        self.notAccessable = False # True if we cannot make a connection back to the other node. Usually means behind a NAT.

        # Identity
        self.localNodeID = uuid.uuid4()
        self.friendlyName = "Unknown"
        self.identity: notrustvars.enclave.security.identity = None

        # Meta
        self.participatingInRoutes:list[brRoute] = []

    def queryPublicKey(self):
        if self.nodeIP:
            requestURL = f'http://{self.nodeIP}:{str(self.webPort)}/pubkey'
            logger.debug(f"Requesting public key from {requestURL}")
            try:
                response = requests.get(url=requestURL)
            except ConnectionRefusedError:
                logger.error("Connection refused when connecting to get public key.")
                return False
            except:
                logger.exception("Python Requests exception when requesting public key...", exc_info=False)
                return False
            if response.status_code != 200:
                return False
            self.identity = notrustvars.enclave.security.identity.newIdentFromPubImport(response.text)
            logger.debug("Public key has been imported successfully.")
            return True
        else:
            logger.error("IP of node not set. Cannot get pubkey. (Check the code)")
            return False
        
    def addRoute(self, route):
        self.participatingInRoutes.append(route)


class brRoute:

    class brRouteType(IntEnum):
        CONTROL = 0
        TEST = 1
        UNENCRYPTED = 2
        ENCRYPTED = 3
        ONION = 4
        HIGHWAY = 5

    def __init__(self, routeType:brRouteType, assignedConnection:socket.socket, thirdParty:brNode):
        self.routeType = routeType 
        self.routeSecret = random.randrange(0, 1000000)
        self.routeID = uuid.uuid4()
        self.assignedConn:socket.socket = assignedConnection
        self.thirdParty:brNode = thirdParty # Would be the node obj
        self.routeThreadLock = threading.Lock()
        self.timeToLive = 0
        self.controllerLastSeen = 0
        self.encryptionUpgraded = False

        # If we are a hop/control, we won't know these
        self.connectingFrom = None # Client on our end we are connecting
        self.connectingTo = None # Would be the client specifically we created this route for
        # We will know this though
        self.weInitiatedConnection = False

        # Connection updates
        self.newNews = False
        self.news = []
        self.newIncoming = False
        self.inbox = []
        self.newOutgoing = False
        self.outbox = []
        self.routeState = "Unknown"

    def isHandShakeComplete(self):
        return self.thirdParty.finishedHandshake
    
    def setHandShakeComplete(self):
        with self.routeThreadLock:
            self.thirdParty.finishedHandshake = True

    def setConnectedState(self, state:bool):
        with self.routeThreadLock:
            self.thirdParty.connected = state

    def thirdPartyPubKeyCheck(self):
        # Just make sure we have the other parties Public key.
        if self.thirdParty.identity == None:
            if self.thirdParty.queryPubKey():
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
        with self.thirdParty.recordThreadLock:
            self.thirdParty.participatingInRoutes.remove(self)

        
class brNodeManager():
    
    def __init__(self, enclave:notrustvars.enclave) -> None:
        self.nodes:dict[str][brNode] = {}
        self.routes:dict[brNode][brRoute] = {}
        self.enc = enclave
        
    def acceptConnection(self, connection:socket.socket, address:tuple):
        
        if address[0] not in self.nodes.keys():
            newNode = brNode(address[0], address[1])
            testRoute = brRoute(brRoute.brRouteType.TEST, connection, newNode)
            newNode.addRoute(testRoute)
            self.nodes[address[0]] = newNode
            self.routes[newNode] = testRoute
            return testRoute
        else:
            node:brNode = self.nodes[address[0]]
            newRoute = brRoute(brRoute.brRouteType.TEST, connection, node)
            node.addRoute(newRoute)
            return newRoute