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
    SUBMIT_KNOWN_NODE = 4
    DHT_REQUEST = 5
    
    # External news triggered
    PEER_ENDPOINT = 6
    PEER_NODE = 7
    
    # Endpoint stuff
    NEW_ENDPOINT_CLIENT = 100
    ENDPOINT_REQUEST = 101
    
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