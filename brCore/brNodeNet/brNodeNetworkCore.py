from enum import IntEnum
import logging
from pathlib import Path
import pprint
from queue import Empty
import random
import socket
import os
import threading
import time
import uuid
import requests
from . import brNodeCoreLog
from brCore.brSockets.brPacket import brPacket
from brCore.brEnclave.Enclave import Enclave
from .brNode import brNode
from ..brSockets.brNetwork import brNetwork
from ..brSockets.brHandshake import brHandshake, brControllerRequest
from .brRoute import brRoute
from .brDHT import brDHT

BR_VERSION = "0.0.1-alpha"

# Backrooms-net route types and levels

# Control Route - Used internally to consistently talk with other nodes to discuss security, opening routes, ect...
# Test Route - Used internally to test the viability of a route.
# Unencrypted - Can be used if the client on the other end handles it's own encryption/doesn't need it.
#   (Levels) None, Hops(1-12)
# Encrypted - Encrypted with each Node's RSA key. (Onion)
#   (Levels) No-Onion, Hops(1)
#            Low, Hops(2-3), 
#            Medium, Hops(4-5),
#            High, Hops(6-12)
# Highway - If there are many connections going out to one client on the network, a highway (Still a route) can be created.
#           By using a highway, which is a single connection, we can bunch up users together to blend their traffic.
#           This hardens against timing attacks.
#
#           When to use? - When we have more than 5 clients going to the same place.
#           Completely optional. It is up to the client to decide if they want to join the highway.
#           A highway will use the most common level 

#
# On the network
#
#               (No Identification)
# Client A (UUID4) --- HOPS --- Client B (UUID4)

# Backrooms message types and explations
#
# 1. Challenge - We have received the public key of the connecting party
# We will give them a random number to decrypt (16 Bytes)
#
# 2. Challenge response - We just send the number back using the originators public key
#
# 3. Ask For Friends - Simply ask for friends
#
# 4. Friend announce - One friend per message
#
# 5. Connection Test - Blank secure message to test latency
#
# 6. Message from client



logger = brNodeCoreLog

class brNodeServer:

    class brNodeServerException(Exception):
        """Exception base class for the brWebServer."""
        pass

    def __init__(self, secureEnclave:Enclave, dhtServer:brDHT, bindAddress:str="127.0.0.1", nodePort:int=13337, webPort:int=11000, debug=False) -> None:

        # If debug is set, we will log at the lowest level + debug timings
        self.debug = debug
        # ------------

        # Network setup
        self.bindAddress = bindAddress
        self.nodePort:int = nodePort
        self.webPort:int = webPort
        # ------------

        # Secure Enclave for peer stats
        self.secureEnclave = secureEnclave
        # ------------
        
        # DHT
        self.dht = dhtServer
        #

        # Connection Pool
        # Will be replaced
        # ------------

        # Network controller specific
        self.uuid = None
        self.knownNodes:dict[str][brNode] = {} # Key is IP address
        # Controller Notes
        # Keys in Enclave:
        # knownNodes
        # ------------

        # Threads
        self.thrLock = threading.Lock()
        self.controllerThread:threading.Thread = None
        # ------------

        # Server state flags
        self.running = False
        self.shutdown = False
        # ------------

        # Socket Control Module
        self.socketControl = brNetwork()

    def startServer(self):
        logger.info("Started node server.")
        if not self.running:
            self.socketControl.startListener(bindAddress="127.0.0.1", nodePort=13337)
            self.socketControl.startInitiator(bindAddress="127.0.0.1")
            self.controllerThread = threading.Thread(name="brNetworkController", target=self.__networkController__, args=[])
            self.routerThread = threading.Thread(name="brNodeNetworkRouter", target=self.__router__, args=[])
            self.routerThread.start()
            self.controllerThread.start()
            
    def shutdownServer(self):
        self.shutdown = True
        self.socketControl.shutdown = True
        logger.info("Sent shutdown signal - Node Main Thread is now waiting...")
        # Fix this later
    
    def generateRoutesFromSeedFile(self, filepath:str='seedservers.txt') -> list[brRoute]:
        allroutes = []
        with open('seedservers.txt') as file:
            for line in file:
                linesplit = line.split(":")
                if len(linesplit) == 3:
                    ip = linesplit[0]
                    port = int(linesplit[1])
                    webport = int(linesplit[2])
                else:
                    ip = line
                    port = 80
                    webport = 443
                try:
                    socket.inet_aton(ip) # Will fail if it isn't a proper IP address
                    newNodeObject = brNode()
                    newNodeObject.nodeIP = ip
                    newNodeObject.nodePort = port
                    newNodeObject.webPort = webport
                    if newNodeObject.queryPubKey():  # TODO: Add check - and ip != usIP
                        pendingRoute = brRoute(brRoute.brRouteType.TEST, None, newNodeObject, brRoute.brConnectionDirection.INITIATED)
                        allroutes.append(pendingRoute)
                    else:
                        logger.error(f'Seed server {ip} did not respond correctly when we asked for their public key. (Security Issue?)')
                except:
                    logger.error(f'A line in the seedservers list is not a valid IP address or seed server. -> {line}')
        return allroutes
    
    def generateRoutesFromEnclaveSave(self)-> list[brRoute]:
        allroutes = []
        nodelist:list[brNode] = self.secureEnclave.returnData("knownNodes")
        for node in nodelist:

            # Since pickle cannot store thread locks, we must be careful and re-populate this
            node.recordThreadLock = threading.Lock()

            pendingRoute = brRoute(brRoute.brRouteType.TEST, None, node, brRoute.brConnectionDirection.INITIATED)
            allroutes.append(pendingRoute)
        
    
    def __debugToFile__(data: bytes, id, count):
        tempdir = Path(f'temp/{id}')
        if not tempdir.is_dir():
            os.mkdir(f'temp/{id}')
        with open(f'temp/{id}/{str(count)}.packet', 'ab') as df:
            df.write(data)
        logger.debug(f'Wrote packet to: temp/{id}/{str(count)}.packet')

    def __router__(self):
        while self.shutdown is False:

            try:
                job:brRoute = self.socketControl.toRouter.get(block=True, timeout=0.15)
            except Empty:
                # This is to be expected a lot
                job = None
                time.sleep(0.25)

            if job is not None:
                if type(job) is brControllerRequest:
                    job:brControllerRequest
                    
                    if job.requesttype is brControllerRequest.requestType.REQUEST_CONFIG_DICT:
                        config = {'uuid': self.uuid, 'dhtport': self.dht.dhtServer.node.port, 'webport': self.webPort}
                        configMessage = brPacket().setMessageType(brPacket.brMessageType.NODE_INFO)
                        configMessage.insertObject(config)
                        job.completeRequest(configMessage.buildPacket())
                    elif job.requesttype is brControllerRequest.requestType.PARSE_RECEIVED_CONFIG:
                        route = job.routeInfo
                        externalConfig = job.data
                        
                        route.externalNode.setNodeUUID(externalConfig['uuid'])
                        route.externalNode.dhtport = externalConfig['dhtport']
                        route.externalNode.webPort = externalConfig['webport']
                        job.completeRequest(brPacket().createSimpleReady())
                    elif job.requesttype is brControllerRequest.requestType.COMPLETE_BASIC_HANDSHAKE:
                        route = job.routeInfo
                        route.externalNode.finishedUnencryptedHandshake = True
                        job.completeRequest()
                #if job.mostRecentPacket is not None:
                #    if job.mostRecentPacket.messageType is brPacket.brMessageType.INTRODUCE and job.externalNode.finishedUnencryptedHandshake is False:
                #        job.outbox.put(brPacket().createSimpleReady())
                #        job.routerPerformedAction()
                #    if job.mostRecentPacket.messageType is brPacket.brMessageType.READY and job.externalNode.finishedUnencryptedHandshake is False:
                #        logger.info("Got ready from unknown node, sending config data")
                #        config = {'uuid': self.uuid, 'dhtport': self.dht.dhtServer.node.port, 'webport': self.webPort}
                #        configMessage = brPacket().setMessageType(brPacket.brMessageType.NODE_INFO)
                #        configMessage.insertObject(config)
                #        job.outbox.put(configMessage.buildPacket())
                #        job.routerPerformedAction()
                #    if job.mostRecentPacket.messageType is brPacket.brMessageType.NODE_INFO and job.externalNode.finishedUnencryptedHandshake is False:
                #        logger.info("Received node info packet from external node")
                #        configobj = job.mostRecentPacket.rebuildObject()
                #        job.externalNode.setNodeUUID(configobj['uuid'])
                #        job.externalNode.dhtport = configobj['dhtport']
                #        job.externalNode.webPort = configobj['webport']
                    
    def __routerOld__(self):
        if packet.messageType == brPacket.brMessageType.INTRODUCE:

            if nodeRoute.thirdParty.identity == None:
                thirdpartyconfig = packet.data.decode('utf-8')
                configSplit = thirdpartyconfig.split('-')
                thirdPartyWebPort = int(configSplit[0])
                thirdPartyNodePort = int(configSplit[1])

                nodeRoute.thirdParty.webPort = thirdPartyWebPort
                nodeRoute.thirdParty.nodePort = thirdPartyNodePort
                if not nodeRoute.thirdPartyPubKeyCheck():
                    logger.error("Could not get public key from node to establish identity!")
                    return False
                
            chunks = nodeRoute.thirdParty.identity.chunkEncrypt(str(nodeRoute.routeSecret).encode('utf-8')) # Should just be one chunk
            reply = brPacket()
            reply.setMessageType(brPacket.brMessageType.CHALLENGE)
            reply.setMessageVersion(BR_VERSION)
            reply.data = chunks[0]
            return reply.buildPacket()
        elif packet.messageType == brPacket.brMessageType.CHALLENGE_RES:
            try:
                result = self.secureEnclave.assignedIdentity.decryptChunk(packet.data)
            except:
                logger.warning(f'Challenge failed against node at {nodeRoute.thirdParty.nodeIP} - possible security breach', exc_info=True)
                return False
            
            try:
                check = int(result)
            except:
                logger.warning(f'Challenge failed against node at {nodeRoute.thirdParty.nodeIP} - bad data - Possible attack')
                return False
            
            if check == nodeRoute.routeSecret:
                nodeRoute.setHandShakeComplete()
                if nodeRoute.routeType == nodeRoute.brRouteType.TEST:
                    nodeRoute.upgradeRouteType(brRoute.brRouteType.CONTROL)
                    with self.thrLock:
                        self.inTesting.remove(nodeRoute)
                        self.controlRoutes.append(nodeRoute)
                reply = brPacket()
                reply.setMessageType(brPacket.brMessageType.ENCR_COMMS)
                reply.setMessageVersion(BR_VERSION)
                return reply.buildPacket()
            else:
                logger.warning(f'Response to our challenge was invalid! Their response: {check}')
                return False
        elif packet.messageType == brPacket.brMessageType.CHALLENGE:
            try:
                result = self.secureEnclave.assignedIdentity.decryptChunk(packet.data)
            except:
                logger.warning(f"Failed to decrypt challenge from third party node at {nodeRoute.thirdParty.nodeIP} - possible attack", exc_info=True)
                return False
            sendback = nodeRoute.thirdParty.identity.chunkEncrypt(result)
            reply = brPacket()
            reply.setMessageType(brPacket.brMessageType.CHALLENGE_RES)
            reply.setMessageVersion(BR_VERSION)
            reply.data = sendback[0]
            return reply.buildPacket()
        elif packet.messageType == brPacket.brMessageType.ENCR_COMMS:
            nodeRoute.setHandShakeComplete()
            nodeRoute.encryptionUpgraded = True
            return True
        elif packet.messageType == brPacket.brMessageType.CALLBACK_PING:
            return True
 
    def __networkController__(self):
        logger.info("Network controller thread started.")
        
        # Get useful network info
        hostname = socket.gethostname()
        usIP = socket.gethostbyname(hostname)
        logger.info(f'Controller reports IP address is: {usIP}')

        # Quickly see if we have saved ourselves a UUID + add stuff to DHT
        if not self.secureEnclave.isEncKey("selfUUID"):
            self.uuid = uuid.uuid4()
            logger.info(f"Network controller new UUID is: {self.uuid}")
            self.secureEnclave.insertData("selfUUID", self.uuid)
        else:
            self.uuid = self.secureEnclave.returnData("selfUUID")
        
        self.dht.setRequest(f'{self.uuid}_pubkey', self.secureEnclave.assignedIdentity.publicKey.save_pkcs1())
        self.dht.setRequest(f'{self.uuid}_nodeport', self.nodePort)
        
        # Rebuild and startup procedure
        # 
        #
        if self.secureEnclave.isEncKey("knownNodes"):
            routes = self.generateRoutesFromEnclaveSave()
            for pendingRoute in routes:
                self.socketControl.connectRequest.put(pendingRoute)
            logger.info(f'Finished adding {len(routes)} routes from the Enclave to reconnect to...')
            
        else:
            if Path('seedservers.txt').is_file():
                routes = self.generateRoutesFromSeedFile('seedservers.txt')
                for pendingRoute in routes:
                    self.socketControl.connectRequest.put(pendingRoute)
                logger.info(f'Finished adding {len(routes)} routes from the Enclave to reconnect to...')

        
        logger.info("Network controller ready.")

        # Local variables for controller

        while not self.shutdown:

            looptime = time.time()
            
            if self.secureEnclave.isEncKey("connect_ip"):
                logger.info("Got connection request from the web server")
                newNodeObject = brNode()
                newNodeObject.nodeIP = self.secureEnclave.returnData("connect_ip")
                newNodeObject.nodePort = self.secureEnclave.returnData("connect_port")
                self.secureEnclave.deleteKey("connect_ip")
                self.secureEnclave.deleteKey("connect_port")
                
                pendingRoute = brRoute(brRoute.brRouteType.TEST, None, newNodeObject, brRoute.brConnectionDirection.INITIATED)
                self.socketControl.connectRequest.put(pendingRoute)
            
            time.sleep(1)
        
        # Broke out, begin shutting down and saving node/route states.
        #logger.info("Controller is waiting for all other threads to shut down before saving...")
        #while self.inboundThread.is_alive() and self.outboundThread.is_alive():
            #time.sleep(0.2)
        
        #TODO: at a later date, make routes restorable
        logger.info("Saving node data - Gathering nodes...")
        nodeGather = []
        for nodeIP in self.knownNodes.keys():
            node:brNode = self.knownNodes[nodeIP]
            node.setNodeDisconnectedState()
            nodeGather.append(node)
        
        self.secureEnclave.updateEntry("knownNodes", nodeGather, True)
            



