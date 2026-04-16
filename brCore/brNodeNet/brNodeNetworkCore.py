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
from ..upnphelper import configureUPNP, removeUPNP
from . import brNodeCoreLog
from .controllerRequest import brControllerRequest
from brCore.brSockets.brPacket import brPacket
from brCore.brEnclave.Enclave import Enclave
from .brNode import brNode
from ..brSockets.brNetwork import ConnectionManager
from .brRoute import brRoute
from ..brSockets.brHandshake import brBasicHandshake
from .router import Router
from .events import EventType, NetworkEvent
from .brDHT import brDHT
from ..brSockets.netconnection import netconnection
from queue import Queue

BR_VERSION = "0.0.1-alpha"

logger = brNodeCoreLog

class brNodeServer:

    class brNodeServerException(Exception):
        """Exception base class for the brWebServer."""
        pass

    def __init__(self, secureEnclave:Enclave, dhtServer:brDHT) -> None:
        
        self.node_port = random.randrange(13000, 14000) # For testing

        self.secureEnclave = secureEnclave
        self.dht = dhtServer
        self.event_queue = Queue(maxsize=10000)
        self.connection_manager = ConnectionManager(secureEnclave, self.event_queue)
        
        self.knownNodes:list[brNode] = []
        self.routes = []
        self.router = Router(self.secureEnclave, self.dht, self.event_queue)
        
        self.shutdown = False
        self.controller_thread = None
        
        # Network controller specific
        self.uuid = None

    def startServer(self):
        #result = configureUPNP(self.nodePort, "TCP", "Backrooms-net Node")
        #if result is not False:
        #    self.externalIP = result
        #    logger.info("UPNP configured for Node Server.")
            
        
        self.connection_manager.startListener("0.0.0.0", self.node_port)
        self.connection_manager.startInitiator()
        self.controllerThread = threading.Thread(name="brNetworkController", target=self._controller_loop, args=[])
        self.controllerThread.start()
        logger.info(f"Started node server on port {self.node_port}")
            
    def shutdownServer(self):
        #removeUPNP(self.nodePort, "TCP")
        self.shutdown = True
        self.socketControl.shutdown = True
        logger.info("Sent shutdown signal - Node Main Thread is now waiting...")
        # Fix this later
        
    def _controller_loop(self):
        logger.info("Network controller started")
        self._perform_initial_bootstrapping()
        
        while not self.shutdown:
            try:
                event: NetworkEvent = self.event_queue.get(timeout=0.3)
                self._handle_event(event)
            except Empty:
                self._do_periodic_maintenance()
                continue
    
    def _handle_event(self, event: NetworkEvent):
        if event.event_type == EventType.CONNECTION_ESTABLISHED:
            self._handle_new_connection(event.route)
        elif event.event_type == EventType.PACKET_RECEIVED:
            self.router.handle_packet(event.route, event.packet)
        elif event.event_type == EventType.CONNECTION_CLOSED:
            self._handle_disconnect(event.route)
        elif event.event_type == EventType.SUBMIT_KNOWN_NODE:
            self.known_nodes.append(event.node)
    
    def _perform_initial_bootstrapping(self):
        try:
            nodelist:list[brNode] = self.secureEnclave.returnData("knownNodes")
        except Enclave.enclaveValueDoesNotExist:
            logger.info("No saved nodes for bootstrap.")
    
    def _do_periodic_maintenance(self):
        pass
    
    def _handle_disconnect(self, route: brRoute):
        pass
    
    def _handle_new_connection(self, route: brRoute):
        # Decide if we need to run handshake
        if route.connectionType == brRoute.brConnectionDirection.INITIATED:
            config = {"uuid": self.uuid, "dhtport": self.dht.serverport}
            brBasicHandshake(route.assignedConn).initiate(config)
        else:
            config = brBasicHandshake(route.assignedConn).receive()
            route.externalNode.setNodeUUID(config["uuid"])
            route.externalNode.dhtport = config["dhtport"]
        # else the receiver side already did it via the handshake class
        self.routes.append(route)
        self.event_queue.put(NetworkEvent(EventType.HANDSHAKE_COMPLETE, route=route))
        
    def connect_to_node(self, ip: str, port: int):
        node = brNode(nodeIP=ip, nodePort=port)
        route = brRoute(
            routeType=brRoute.brRouteType.TEST,
            externalNode=node,
            connectionType=brRoute.brConnectionDirection.INITIATED
        )
        
        # Put the request into the ConnectionManager's dedicated queue
        self.connection_manager.connect_request_queue.put(route)

    def __router__(self):
        while self.shutdown is False:

            try:
                job:brControllerRequest = self.socketControl.toRouter.get(block=True, timeout=0.15)
            except Empty:
                # This is to be expected a lot
                job = None
                time.sleep(0.25)

            if job is not None:
                match job.controllerRequestType:
                    
                    case brControllerRequest.requestType.SUBMIT_KNOWN_NODE:
                        logger.info(f"Added {job.node.localNodeID} to the known nodes list")
                        self.knownNodes.append(job.node)
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

        # Quickly see if we have saved ourselves a UUID + add stuff to DHT
        if not self.secureEnclave.isEncKey("selfUUID"):
            self.uuid = uuid.uuid4()
            logger.info(f"Network controller new UUID is: {self.uuid}")
            self.secureEnclave.insertData("selfUUID", self.uuid)
            self.secureEnclave.insertData("webPort", self.webPort)
        else:
            self.uuid = self.secureEnclave.returnData("selfUUID")
        
        # Values that need to be updated every startup
        self.secureEnclave.updateEntry("webPort", self.webPort)
        self.secureEnclave.updateEntry("dhtPort", self.dht.serverport)
        
        if self.dht.hasBootStrapped:
            self.dht.setRequest(f'{self.uuid}_pubkey', self.secureEnclave.assignedIdentity.publicKey.save_pkcs1())
            self.dht.setRequest(f'{self.uuid}_nodeport', self.nodePort)
        else:
            logger.error("DHT is not bootstrapped yet. Cannot publish our public key or node port yet.")
        
        # Rebuild and startup procedure
        # 
        #
        if self.secureEnclave.isEncKey("knownNodes"):
            routes = self.generateRoutesFromEnclaveSave()
            if routes is not None:
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

        # Main Controller Loop
        #
        #

        while not self.shutdown:

            looptime = time.time()
            
            if self.secureEnclave.isEncKey("connect_ip"):
                logger.info("Got connection request from the web server")
                newNodeObject = brNode(nodeIP=self.secureEnclave.returnData("connect_ip"), nodePort=self.secureEnclave.returnData("connect_port"))
                self.secureEnclave.deleteKey("connect_ip")
                self.secureEnclave.deleteKey("connect_port")
                
                pendingRoute = brRoute(routeType=brRoute.brRouteType.TEST, externalNode=newNodeObject, connectionType=brRoute.brConnectionDirection.INITIATED)
                self.socketControl.connectRequest.put(pendingRoute)
                
            if self.dht.hasBootStrapped is False:
                bootstraplist = []
                for node in self.knownNodes:
                    if node.dhtport != 0:
                        bootstraplist.append((node.nodeIP,node.dhtport))
                if len(bootstraplist) > 0:
                    self.dht.setBootstrapList(bootstraplist)
            
            time.sleep(1)
        
        # Broke out, begin shutting down and saving node/route states.
        #logger.info("Controller is waiting for all other threads to shut down before saving...")
        #while self.inboundThread.is_alive() and self.outboundThread.is_alive():
            #time.sleep(0.2)
        
        #TODO: at a later date, make routes restorable
        logger.info("Saving node data - Gathering nodes...")
        for node in self.knownNodes:
            node.setNodeDisconnectedState()
  
        self.secureEnclave.updateEntry("knownNodes", self.knownNodes, True)
            



