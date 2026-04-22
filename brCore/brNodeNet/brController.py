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
from brCore.brSockets.brPacket import brPacket
from brCore.brEnclave.Enclave import Enclave
from .brNode import brNode
from ..brSockets.brNetwork import ConnectionManager
from .brRoute import brRoute
from ..brSockets.brHandshake import brBasicHandshake
from .router import Router
from .events import EventType, NetworkEvent, DHTRequest, EndPointEvent
from .brDHT import brDHT
from ..brSockets.netconnection import netconnection
from .brEndpoint import brEndpoint
from .controllertasks import ControllerTask, TaskType
from queue import Queue

BR_VERSION = "0.0.1-alpha"

logger = brNodeCoreLog

class brNodeServer:

    class brNodeServerException(Exception):
        """Exception base class for the brWebServer."""
        pass

    def __init__(self, secureEnclave:Enclave, dhtServer:brDHT, webport:int) -> None:
        
        self.node_port = random.randrange(13000, 14000) # For testing
        self.web_port = webport

        self.secureEnclave = secureEnclave
        self.dht = dhtServer
        self.event_queue = Queue(maxsize=10000)
        self.dht_queue = Queue(maxsize=10000)
        self.controller_tasks = Queue(maxsize=10000)
        self.connection_manager = ConnectionManager(secureEnclave, self.event_queue)
        
        self.knownNodes:list[brNode] = []
        self.dhtResponses:dict[str][DHTRequest] = {}
        self.router = Router(self.secureEnclave, self.dht, self.event_queue, self.connection_manager)
        
        self.shutdown = False
        self.controller_thread = None
        self.total_events = 0
        
        self.config = None
        
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
        self.connection_manager.shutdown = True
        logger.info("Sent shutdown signal - Node Main Thread is now waiting...")
        # Fix this later
        
    def _debug_event(self, event: NetworkEvent):
        match event:
            case NetworkEvent():
                logger.info(f'EVENT: NETWORK EVENT, ROUTE-{event.route.routeID}, EVENTTYPE: {event.event_type.name}')
                if event.error is not None:
                    logger.exception("An exception happened during the last Network event.", exc_info=event.error)
            case DHTRequest():
                logger.info(f'EVENT: DHT EVENT, KEY-{event.key}')
            case EndPointEvent():
                logger.info(f'EVENT: ENDPOINTEVENT, ID-{event.endPoint.endpoint_uuid}, EVENTTYPE: {event.event_type.name}')
                      
    def _controller_loop(self):
        logger.info("Network controller started")
        self._initial_persistant_task_setup()
        self._prestart()
        
        while not self.shutdown:
            try:
                event = self.event_queue.get(timeout=0.3)
                self._debug_event(event) # Just comment out when not needed
                self._handle_event(event)
                self.total_events += 1
            except Empty:
                self._do_scheduled_tasks()
                
    
    def _initial_persistant_task_setup(self):
        self.controller_tasks.put(ControllerTask.create_persistent_task(TaskType.EVAL_CONTROL_CONS, 300))
        self.controller_tasks.put(ControllerTask.create_persistent_task(TaskType.READ_NEWS, 60))
        self.controller_tasks.put(ControllerTask.create_persistent_task(TaskType.MAINTAIN_ENC_RECORD, 300))
        self.controller_tasks.put(ControllerTask.create_persistent_task(TaskType.LOCAL_DHT_TTL_CLEANUP, 300))
    
    def _prestart(self):
        # Restore the UUID so that other nodes know who we are
        if not self.secureEnclave.isEncKey("selfUUID"):
            self.uuid = uuid.uuid4()
            logger.info(f"Network controller new UUID is: {self.uuid}")
            self.secureEnclave.insertData("selfUUID", self.uuid)
        else:
            self.uuid = self.secureEnclave.returnData("selfUUID")
            
        # Set basic handshake info object
        self.config = {"uuid": self.uuid, "dhtport": self.dht.serverport, "webport": self.web_port}
        self.router.config = self.config
    
    def _handle_event(self, event: NetworkEvent):
        
        if event.event_type == EventType.CONNECTION_ESTABLISHED:
            self._handle_new_connection(event.route)
        elif event.event_type == EventType.PACKET_RECEIVED:
            self.router.handle_packet(event.route, event.packet)
        elif event.event_type == EventType.CONNECTION_CLOSED:
            self._handle_disconnect(event.route)
        elif event.event_type == EventType.SUBMIT_KNOWN_NODE:
            self._submit_known_node(event.route)
        elif event.event_type == EventType.NEW_ENDPOINT_CLIENT:
            self.router.handle_new_endpoint(event.endPoint)
        elif event.event_type == EventType.ENDPOINT_REQUESTS_FIND_TARGET:
            pass
        elif event.event_type == EventType.DHT_REQUEST:
            self._handle_DHT_response()
    
    # Local 
    # 
    def _handle_disconnect(self, route: brRoute):
        pass
    
    def _handle_new_connection(self, route: brRoute):
        # Decide if we need to run handshake
        if route.connectionType == brRoute.brConnectionDirection.INITIATED:
            first_hello = brPacket()
            first_hello.setMessageType(brPacket.brMessageType.INTRODUCE)
            self.router._send_to_route(route, first_hello)
            route.connectingTo = f'{route.externalNode.localNodeID} (Unconfirmed)'
            route.connectingFrom = self.uuid
        else:
            route.connectingFrom = self.uuid
            route.connectingTo = f'{route.externalNode.localNodeID} (Unconfirmed)'
    
    def _submit_known_node(self, route:brRoute):
        self.knownNodes.append(route.externalNode)
        self.router._perform_route_upgrade(route)
        if len(self.knownNodes) > 0 and len(self.dht.dhtServer.bootstrappable_neighbors()) == 0:
            self.dht.setBootstrapList([(route.externalNode.nodeIP, route.externalNode.dhtport)])
            logging.info("Just bootstrapped the DHT network.")
    
    def _handle_DHT_response(self, response:DHTRequest):
        if response.forController:
            self.dht_queue.put(response)
        else:
            self.dhtResponses[response.request_id] = response
    
    def connect_to_node(self, ip: str, port: int):
        node = brNode(nodeIP=ip, nodePort=port, connected=True)
        route = brRoute(
            routeType=brRoute.brRouteType.TEST,
            externalNode=node,
            connectionType=brRoute.brConnectionDirection.INITIATED
        )
        
        # Put the request into the ConnectionManager's dedicated queue
        self.connection_manager.connect_request_queue.put(route)

    # Tasks
    # 
    def _do_scheduled_tasks(self):
        started = time.time()
        end = started + 1 # Yes, for one second we can do tasks.
        
        
        while not self.shutdown and (end < time.time()):
            try:
                task:ControllerTask = self.controller_tasks.get(timeout=0.3)
                if task.persistent:
                    self._handle_task(task)
                    task.last_executed = time.time()
                    self.controller_tasks.put(task)
                    continue
                
                if task.isexetime():
                    self._handle_task(task)
                    
            except Empty:
                break
    
    def _handle_task(self, task: ControllerTask):
        if task.task_type == TaskType.LOCAL_DHT_TTL_CLEANUP:
            self._local_dht_ttl_cleanup()
        elif task.task_type == TaskType.MAINTAIN_ENC_RECORD:
            self._maintain_enc_record(task)
        elif task.task_type == TaskType.MAINTAIN_DHT:
            self._maintain_dht(task)
        elif task.task_type == TaskType.EVAL_CONTROL_CONS:
            self._eval_control_cons(task)
        elif task.task_type == TaskType.READ_NEWS:
            self._controller_read_news(task)
    
    def _local_dht_ttl_cleanup(self):
        removed = 0
        for key in self.dhtResponses.keys():
            check_response = self.dhtResponses[key]
            if (time.time() - check_response.created_at >= check_response.time_to_live_seconds):
                self.dhtResponses.pop(key)
                removed += 1
        if removed > 0:
            logger.info(f'Removed {removed} DHT Responses that expired.')
    
    def _maintain_enc_record(self, task:ControllerTask):
        #if self.secureEnclave.isEncKey("knownNodes"):
        #    self.secureEnclave.returnData("knownNodes")
        #else:
        #    logger.info("Bootstrapping the local node with previously known nodes.")
        logger.info("Maintain Enclave Task ran successfully.")
    
    def _maintain_dht(self, task:ControllerTask):
        logger.info("Maintain DHT Task ran successfully.")
        
    def _maintain_dht(self, task:ControllerTask):
        logger.info("Maintain DHT Task ran successfully.")
    
    def _eval_control_cons(self, task:ControllerTask):
        logger.info("Maintain DHT Task ran successfully.")
        
    def _controller_read_news(self, task:ControllerTask):
        all_control_routes = self.router.fetch_all_control_routes()
        logger.info(f"Controller has {len(all_control_routes)} control routes.")
        
    
                    
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
            



