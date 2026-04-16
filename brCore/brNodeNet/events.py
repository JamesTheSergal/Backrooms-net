from dataclasses import dataclass
from enum import IntEnum
from .brRoute import brRoute
from ..brSockets.brPacket import brPacket

class EventType(IntEnum):
    CONNECTION_ESTABLISHED = 0
    CONNECTION_CLOSED = 1
    HANDSHAKE_COMPLETE = 2
    PACKET_RECEIVED = 3
    ROUTE_UPGRADE_REQUEST = 4
    SUBMIT_KNOWN_NODE = 5
    DHT_SET = 6
    DHT_GET = 7
    DHT_RESPONSE = 8
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