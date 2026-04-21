from dataclasses import dataclass, field
from enum import IntEnum
from .brRoute import brRoute
from ..brSockets.brPacket import brPacket
from .brEndpoint import brEndpoint
import time

class EventType(IntEnum):
    CONNECTION_ESTABLISHED = 0
    CONNECTION_CLOSED = 1
    HANDSHAKE_COMPLETE = 2
    PACKET_RECEIVED = 3
    ROUTE_UPGRADE_REQUEST = 4
    SUBMIT_KNOWN_NODE = 5
    NEW_ENDPOINT_CLIENT = 100
    GET_ENDPOINT_FROM_TOKEN = 101
    ENDPOINT_REQUESTS_FIND_TARGET = 102
    
    # Add more as needed: DHT_BOOTSTRAP_NEEDED, etc.

@dataclass
class NetworkEvent:
    event_type: EventType
    route: brRoute = None
    packet: brPacket = None
    node = None          # for SUBMIT_KNOWN_NODE etc.
    error: Exception = None
    
@dataclass
class DHTRequest:
    """Used for both GET and SET requests."""
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