import time
import uuid
import secrets
from dataclasses import field, dataclass
from brCore.brEnclave.Identity import Identity
from .brRoute import brRoute
from . import brNodeCoreLog
logger = brNodeCoreLog


# Endpoint is basically just a client connected to our node wanting to partake in a route.
# We will not record the IP address or port here. No need for client security.
# They will definately need to use a session secret though.
# Encrypting traffic between the node and endpoint are optional.

@dataclass
class brEndpoint:
    endpoint_uuid: uuid.UUID = field(default_factory=uuid.uuid4)
    requested_target: uuid.UUID = None
    searching_for_target: bool = False
    requested_route_type: brRoute.brRouteType = None
    provided_route: brRoute = None
    identity: Identity = None
    session_secret:str = field(default_factory=lambda: secrets.token_urlsafe(32))
    first_seen: float = field(default_factory=time.time)
    last_seen: float = 0
    getdhthistory: list = field(default_factory=list)
    setdhthistory: list = field(default_factory=list)
    
    def seenNow(self):
        self.last_seen = time.time()
        return self
    
    def add_dht_key_get_history(self, key):
        if key not in self.getdhthistory:
            self.getdhthistory.append(key)
    
    def add_dht_key_set_history(self, key):
        if key not in self.setdhthistory:
            self.getdhthistory.append(key)
            
    def addPublicKey(self, public_key_str):
        self.identity = Identity().newIdentFromPubImport(public_key_str)
        logger.info(f'Endpoint {self.endpoint_uuid} just confirmed their identity')
