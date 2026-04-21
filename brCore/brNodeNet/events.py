from dataclasses import dataclass, field
from enum import IntEnum
from .brRoute import brRoute
from .brNode import brNode
from ..brSockets.brPacket import brPacket
from .brEndpoint import brEndpoint
import time

class EventType(IntEnum):
    
    # Local events
    CONNECTION_ESTABLISHED = 0
    CONNECTION_CLOSED = 1
    HANDSHAKE_COMPLETE = 2
    PACKET_RECEIVED = 3
    ROUTE_UPGRADE_REQUEST = 4
    SUBMIT_KNOWN_NODE = 5
    DHT_REQUEST = 6
    
    # External news triggered
    PEER_ENDPOINT = 7
    PEER_NODE = 8
    
    # Endpoint stuff
    NEW_ENDPOINT_CLIENT = 100
    ENDPOINT_REQUESTS_FIND_TARGET = 101
    
    # Add more as needed: DHT_BOOTSTRAP_NEEDED, etc.



@dataclass
class NetworkEvent:
    event_type: EventType
    route: brRoute = None
    packet: brPacket = None
    error: Exception = None
    
@dataclass
class DHTRequest:
    """Used for both GET and SET requests."""
    event_type: EventType
    key: str
    value: any = None           # Only used for SET
    request_id: str = None      # Unique ID so you can match responses
    created_at: float = field(default_factory=time.time)
    time_to_live_seconds: int = 30
    forController = False
    
@dataclass
class EndPointEvent:
    event_type: EventType
    endPoint: brEndpoint = None