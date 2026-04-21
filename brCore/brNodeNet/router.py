from queue import Queue
import time
from typing import Optional
from . import brNodeCoreLog
from .events import NetworkEvent, EventType
from .brRoute import brRoute
from .brEndpoint import brEndpoint
from ..brSockets.brPacket import brPacket
from ..brEnclave.Enclave import Enclave
from .brDHT import brDHT

logger = brNodeCoreLog


class Router:
    """
    Responsible for all decision making about what to do with incoming packets
    and route lifecycle events.
    
    This replaces the scattered logic that was previously in __router__ and
    __routerOld__ in brNodeNetworkCore.py.
    
    The NetworkController should call router.handle_event(event) for every
    NetworkEvent it receives.
    """
    
    def __init__(self, secure_enclave: Enclave, dht: brDHT, event_queue: Queue):
        self.secure_enclave = secure_enclave
        self.dht = dht
        self.event_queue = event_queue
        self.config = None
        
        # You can keep a local reference to active routes, or let the 
        # controller be the source of truth and always pass the route in.
        self.active_routes: list[brRoute] = []
        self.active_endpoints: dict[str][brEndpoint] = {}
        
        logger.info("Router initialized.")

    def handle_event(self, event: NetworkEvent):
        """Main entry point. The controller should call this for every event."""
        if event.event_type == EventType.PACKET_RECEIVED:
            if event.route and event.packet:
                self.handle_packet(event.route, event.packet)
        elif event.event_type == EventType.CONNECTION_ESTABLISHED:
            self.handle_new_route(event.route)
        elif event.event_type == EventType.CONNECTION_CLOSED:
            self.handle_route_closed(event.route)
        elif event.event_type == EventType.ROUTE_UPGRADE_REQUEST:
            self._perform_route_upgrade(event.route)
        # Add more event types here as you expand the system

    def handle_packet(self, route: brRoute, packet: brPacket):
        """Core packet routing logic based on route type and message type."""
        if not route or not packet:
            logger.warning("Router received invalid packet or route")
            return

        logger.debug(f"Router handling {packet.messageType.name} on "
                    f"route {route.routeID} (type: {route.routeType.name})")

        # === Universal control/handshake messages (all route types) ===
        if packet.messageType in (
            brPacket.brMessageType.INTRODUCE,
            brPacket.brMessageType.READY,
            brPacket.brMessageType.NODE_INFO,
            brPacket.brMessageType.CHALLENGE,
            brPacket.brMessageType.CHALLENGE_RES,
            brPacket.brMessageType.ENCR_COMMS,
        ):
            self._handle_handshake_messages(route, packet)
            return

        # === Route-type specific handling ===
        match route.routeType:
            case brRoute.brRouteType.TEST:
                self._handle_test_route(route, packet)
            case brRoute.brRouteType.CONTROL:
                self._handle_control_route(route, packet)
            case brRoute.brRouteType.UNENCRYPTED:
                self._handle_unencrypted_route(route, packet)
            case brRoute.brRouteType.ENCRYPTED:
                self._handle_encrypted_route(route, packet)
            case brRoute.brRouteType.ONION:
                self._handle_onion_route(route, packet)
            case brRoute.brRouteType.HIGHWAY:
                self._handle_highway_route(route, packet)
            case _:
                logger.warning(f"Unknown route type: {route.routeType}")

    def handle_new_route(self, route: brRoute):
        """Called when a new connection is fully established."""
        if route not in self.active_routes:
            self.active_routes.append(route)
        
        logger.info(f"New route established: {route.routeID} "
                   f"to {route.externalNode.nodeIP}")
        
        # Submit the node to the controller's knownNodes list via event
        self.event_queue.put(NetworkEvent(
            event_type=EventType.SUBMIT_KNOWN_NODE,
            route=route,
            node=route.externalNode
        ))
        
        # If this was an outbound connection, we may want to start handshake
        if route.connectionType == brRoute.brConnectionDirection.INITIATED:
            self._start_handshake(route)

    def handle_route_closed(self, route: brRoute):
        """Clean up when a route disconnects."""
        if route in self.active_routes:
            self.active_routes.remove(route)
        logger.info(f"Route closed: {route.routeID}")
        # You can notify the controller or save state here if needed

    def handle_new_endpoint(self,endpoint:brEndpoint):
        if endpoint.session_secret not in self.active_endpoints.keys():
            self.active_endpoints[endpoint.session_secret] = endpoint
            
            logger.info(f"New endpoint established: {endpoint.endpoint_uuid}")

    # ====================== Private Handlers ======================

    def _handle_handshake_messages(self, route: brRoute, packet: brPacket):
        """
        Contains the logic that used to live in __routerOld__.
        This is a good place to consolidate all handshake / initial 
        negotiation logic.
        """
        msg_type = packet.messageType
        
        if msg_type == brPacket.brMessageType.INTRODUCE:
            # Handle introduction from a new node
            self._process_introduce(route, packet)
            
        elif msg_type == brPacket.brMessageType.CHALLENGE:
            self._respond_to_challenge(route, packet)
            
        elif msg_type == brPacket.brMessageType.CHALLENGE_RES:
            self._verify_challenge_response(route, packet)
            
        elif msg_type == brPacket.brMessageType.NODE_INFO:
            self._process_node_info(route, packet)
            
        elif msg_type == brPacket.brMessageType.ENCR_COMMS:
            route.encryptionUpgraded = True
            route.setHandShakeComplete()
            logger.info(f"Encryption upgraded on route {route.routeID}")
            # Optionally upgrade TEST -> CONTROL here
            if route.routeType == brRoute.brRouteType.TEST:
                self.upgrade_route(route, brRoute.brRouteType.CONTROL)

    def _handle_test_route(self, route: brRoute, packet: brPacket):
        
        if route.externalNode.finishedBasicHandshake == False:
             match packet.messageType:
                case brPacket.brMessageType.INTRODUCE:
                    self._send_to_route(route, brPacket().createSimpleReady())
                case brPacket.brMessageType.READY:
                    self._send_to_route(route, brPacket().createNodeInfo(self.config))
                case brPacket.brMessageType.NODE_INFO:
                    config = packet.rebuildObject()
                    route.externalNode.setNodeUUID(config["uuid"])
                    route.externalNode.dhtport = config["dhtport"]
                    self.active_routes.append(route)
                    if not route.connectionType == brRoute.brConnectionDirection.INITIATED:
                       self._send_to_route(route, brPacket().createNodeInfo(self.config)) 
                       
                    # Set done with basic handshake after node info exchanged on both sides.
                    route.setBasicHandShakeComplete()
        
        """Test routes are usually upgraded quickly to CONTROL."""
        if packet.messageType == brPacket.brMessageType.CALLBACK_PING:
            if (time.time() - route.controllerLastSeen) > 5:
                route.setRouteStateIdle()
                # Send a ping back or upgrade the route
                self._send_ping(route)
                route.controllerLastSeenNow()
        else:
            logger.debug(f"Test route received non-ping message: {packet.messageType}")

    def _handle_control_route(self, route: brRoute, packet: brPacket):
        """Control routes are used for management, DHT, friend announcements, etc."""
        if packet.messageType == brPacket.brMessageType.ASK_FOR_FRIENDS:
            self._send_friend_announce(route)
        elif packet.messageType == brPacket.brMessageType.FRIEND_ANNOUNCE:
            self._process_friend_announce(route, packet)
        # Add more control message types here

    def _handle_unencrypted_route(self, route: brRoute, packet: brPacket):
        """Simple passthrough for unencrypted traffic."""
        # Forward to client or higher layer via another event
        pass

    def _handle_encrypted_route(self, route: brRoute, packet: brPacket):
        """Handle onion-style or direct encrypted messages."""
        # Decrypt using route keys, then process inner payload
        pass

    def _handle_onion_route(self, route: brRoute, packet: brPacket):
        """Layered onion routing logic would go here."""
        pass

    def _handle_highway_route(self, route: brRoute, packet: brPacket):
        """Highway (multiplexed) route handling."""
        pass

    # ====================== Helper Methods ======================

    def upgrade_route(self, route: brRoute, new_type: brRoute.brRouteType):
        """Request a route type upgrade (e.g. TEST -> CONTROL)."""
        if route.routeType != new_type:
            route.upgradeRouteType(new_type)
            self.event_queue.put(NetworkEvent(
                event_type=EventType.ROUTE_UPGRADE_REQUEST,
                route=route
            ))
            logger.info(f"Requested upgrade of route {route.routeID} to {new_type.name}")

    def _send_to_route(self, route: brRoute, packet: brPacket, encrypt: bool = True):
        """Convenience method to queue a packet for sending."""
        if not route or not route.outbox:
            return False
        
        data = packet.buildPacket()
        # If encryption logic is needed, do it here or in the connection layer
        route.outbox.put(data)
        route.setRouteStateBusy()
        return True

    def _send_ping(self, route: brRoute):
        """Helper to send a callback ping."""
        ping = brPacket().createCallbackPing()
        self._send_to_route(route, ping, encrypt=False)

    def _start_handshake(self, route: brRoute):
        """Kick off the handshake sequence for a new outbound route."""
        hello = brPacket().setMessageType(brPacket.brMessageType.INTRODUCE)
        hello.setMessageVersion("0.0.1-alpha")  # Use your BR_VERSION
        self._send_to_route(route, hello, encrypt=False)

    # ====================== Stub Methods (fill these in) ======================

    def _process_introduce(self, route: brRoute, packet: brPacket):
        if route.externalNode.finishedBasicHandshake == False:
            self._send_to_route(route, brPacket().createSimpleReady())

    def _respond_to_challenge(self, route: brRoute, packet: brPacket):
        logger.info("TODO: Implement challenge response")
        
    def _verify_challenge_response(self, route: brRoute, packet: brPacket):
        logger.info("TODO: Implement challenge verification")
        # On success, call self.upgrade_route(...)

    def _process_node_info(self, route: brRoute, packet: brPacket):
        logger.info("TODO: Process NODE_INFO packet")
        # Update route.externalNode with UUID, ports, etc.

    def _send_friend_announce(self, route: brRoute):
        logger.info("TODO: Send friend announce packet")

    def _process_friend_announce(self, route: brRoute, packet: brPacket):
        logger.info("TODO: Process incoming friend announce")
        
    def _perform_route_upgrade(self, route: brRoute):
        """Called after a ROUTE_UPGRADE_REQUEST event."""
        logger.debug(f"Route {route.routeID} upgraded to {route.routeType.name}")
        # Any post-upgrade logic can go here
