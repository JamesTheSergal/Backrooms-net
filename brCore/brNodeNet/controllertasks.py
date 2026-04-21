from dataclasses import dataclass, field
from enum import IntEnum
import json
import time
from .events import NetworkEvent

class TaskType(IntEnum):
    READ_NEWS = 0
    MAINTAIN_DHT = 2
    MAINTAIN_ENC_RECORD = 3
    LOCAL_DHT_TTL_CLEANUP = 4
    EVAL_CONTROL_CONS = 5
    BROADCAST_LOCAL_ENDPOINT = 7        # By telling other nodes around us that we have an endpoint, it can speed up interactions rather than looking up
                                        # the endpoint UUID in the DHT.
                                        
    BROADCAST_LOCAL_TRANSIT_ROUTES = 8  # FEATURE IDEA: do this to allow other nodes to know who has what. We can also broadcast node shutdowns and use the routes we 
                                        # know about to pick up the slack from the failed node.
                                        

    
@dataclass
class ControllerTask:
    task_type: TaskType
    json_news: str = None
    last_executed: float = field(default_factory=time.time)
    execute_every: int = 0 # Seconds
    persistent:bool = False 
    
    def isexetime(self):
        if self.persistent:
            time_since_last = int((time.time() - self.last_executed))
            if int(time.time() + time_since_last) > self.execute_every:
                return True
            else:
                return False
        else:
            return True
        
    def create_persistent_task(task_type: TaskType, repeat_seconds:int = 60):
        return ControllerTask(task_type, execute_every=repeat_seconds, persistent=True)
    


    