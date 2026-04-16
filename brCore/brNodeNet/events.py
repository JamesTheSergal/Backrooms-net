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
    # Add more as needed: DHT_BOOTSTRAP_NEEDED, etc.

@dataclass
class NetworkEvent:
    event_type: EventType
    route: brRoute = None
    packet: brPacket = None
    node = None          # for SUBMIT_KNOWN_NODE etc.
    error: Exception = None