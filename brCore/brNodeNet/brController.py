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
import schedule
from schedule import every, repeat, run_pending
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
from .brDHT import brDHT, brDHTQueryHelper
from ..brSockets.netconnection import netconnection
from .brEndpoint import brEndpoint
from .controllertasks import ControllerTask, TaskType
from queue import Queue
import json

BR_VERSION = "0.0.1-alpha"

logger = brNodeCoreLog

class brNodeServer:

    class brNodeServerException(Exception):
        """Exception base class for the brWebServer."""
        pass

    def __init__(self, secureEnclave:Enclave, dhtServer:brDHT, webport:int) -> None:
        self.secureEnclave = secureEnclave
        
        # Restore the UUID so that other nodes know who we are
        if not self.secureEnclave.isEncKey("selfUUID"):
            self.uuid = uuid.uuid4()
            logger.info(f"Network controller new UUID is: {self.uuid}")
            self.secureEnclave.insertData("selfUUID", self.uuid)
        else:
            self.uuid = self.secureEnclave.returnData("selfUUID")
            
        # Settings
        self.node_port = random.randrange(13000, 14000) # For testing
        self.web_port = webport
        self.max_control_routes:int = 10

        self.dht = dhtServer
        self.dht_query = brDHTQueryHelper(dhtServer, secureEnclave)
        self.event_queue = Queue(maxsize=10000)
        self.dht_queue = Queue(maxsize=10000)
        self.connection_manager = ConnectionManager(secureEnclave, self.event_queue)
        
        self.knownNodes:list[brNode] = []
        self.dhtResponses:dict[str][DHTRequest] = {}
        self.router = Router(self.uuid, self.secureEnclave, self.dht, self.event_queue, self.connection_manager)
        
        self.shutdown = False
        self.controller_thread = None
        self.total_events = 0
        
        # Set basic handshake info object
        self.config = {"uuid": self.uuid, "dhtport": self.dht.serverport, "webport": self.web_port, "nodeport": self.node_port}
        self.router.config = self.config
        
        
        
        

    def startServer(self):
        #result = configureUPNP(self.nodePort, "TCP", "Backrooms-net Node")
        #if result is not False:
        #    self.externalIP = result
        #    logger.info("UPNP configured for Node Server.")
        self.externalIP = "127.0.0.1"
            
        
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
        
        while not self.shutdown:
            try:
                event = self.event_queue.get(timeout=0.3)
                self._debug_event(event) # Just comment out when not needed
                self._handle_event(event)
                self.total_events += 1
                continue
            except Empty:
                pass
            
            schedule.run_pending()
                
    
    def _initial_persistant_task_setup(self):
        schedule.every(5).minutes.do(brNodeServer._local_dht_ttl_cleanup, self)
        schedule.every(5).minutes.do(brNodeServer._maintain_enc_record, self)
        schedule.every(5).minutes.do(brNodeServer._maintain_dht, self)
        schedule.every().minute.do(brNodeServer._eval_control_cons, self)
        schedule.every(30).seconds.do(brNodeServer._controller_read_news, self)
        
    
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
        elif event.event_type == EventType.ENDPOINT_REQUEST:
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
            route.setDestinations(origin=self.uuid, destination=f'{route.externalNode.localNodeID} (unconfirmed)')
            self.router.initiate_handshake(route)
        else:
            pass
            route.setDestinations(origin=f'{route.externalNode.localNodeID} (unconfirmed)', destination=self.uuid)
    
    def _submit_known_node(self, route:brRoute):
        self.knownNodes.append(route.externalNode)
        if len(self.knownNodes) == 1:
            self.router.negotiate_control_route(route)
            logger.info("No other nodes connected, automatically attempting to upgrade route to CONTROL.")
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
    def _local_dht_ttl_cleanup(self):
        removed = 0
        for key in self.dhtResponses.keys():
            check_response = self.dhtResponses[key]
            if (time.time() - check_response.created_at >= check_response.time_to_live_seconds):
                self.dhtResponses.pop(key)
                removed += 1
        if removed > 0:
            logger.info(f'Removed {removed} DHT Responses that expired.')
    
    def _maintain_enc_record(self):
        #if self.secureEnclave.isEncKey("knownNodes"):
        #    self.secureEnclave.returnData("knownNodes")
        #else:
        #    logger.info("Bootstrapping the local node with previously known nodes.")
        logger.info("Maintain Enclave Task ran successfully.")
    
    def _maintain_dht(self):
        if not self.dht.hasBootStrapped:
            logger.error("Maintain DHT task failed because we are not bootstrapped yet.")
            
        # Refresh node info
        self.dht_query.publish(self.uuid, "node")
        self.dht_query.publish(self.uuid, self.secureEnclave.assignedIdentity.publicKey.save_pkcs1().decode("utf-8"), "pubkey")
        self.dht_query.publish(self.uuid, self.web_port, "webport")
        self.dht_query.publish(self.uuid, self.node_port, "nodeport")
        self.dht_query.publish(self.uuid, self.dht.serverport, "dhtport")
        self.dht_query.publish(self.uuid, self.externalIP, "address")
        
        # Refresh endpoint info
        for endpoint_key in self.router.active_endpoints.keys():
            endpoint:brEndpoint = self.router.active_endpoints[endpoint_key]
            self.dht_query.publish(endpoint.endpoint_uuid, "endpoint")
            self.dht_query.publish(endpoint.endpoint_uuid, str(self.uuid), typestr="endpoint")
            
        known = []
        for node in self.knownNodes:
            known.append(str(node.localNodeID)) 
        self.dht_query.publish(self.uuid, json.dumps(known), typestr="knownnodes")
        
        for route in self.router.active_routes:
            self.dht_query.publish(route.routeID, "route")
            self.dht_query.publish(route.routeID, route.originID, "origin")
            self.dht_query.publish(route.routeID, route.destinationID, "destination")
            self.dht_query.publish(route.routeID, route.routeType.name, "type")
            
    def _eval_control_cons(self):
        
        # Evaluate test routes
        
        control_routes_active = self.router.fetch_all_control_routes()
        
        logger.info(f'Controller has {len(control_routes_active)} active controls')
        
        #for route in self.router.fetch_all_test_routes():
        #    route:brRoute
        #    if control_routes_active < self.max_control_routes:
        #        logger.info("TEST: C")
    
    def _controller_read_news(self):
        all_control_routes = self.router.fetch_all_control_routes()
        logger.info(f"Controller has {len(all_control_routes)} control routes.")

