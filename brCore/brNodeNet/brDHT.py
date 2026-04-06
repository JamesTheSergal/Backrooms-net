import re
import asyncio
from queue import Queue
import time
from brCore.brNodeNet import brDHTLog as log
from kademlia.network import Server
from threading import Thread
import logging

# Get a list of IP addresses and ports from bootstrapdht.txt
def dht_file_read():
    pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})'
    filename = "brCore/bootstrapdht.txt"
        
    dht_addresses = []

    try: 
        with open("brCore/bootstrapdht.txt") as file:
            for line in file:
                    # Find all matches in the current line
                    matches = re.findall(pattern, line.strip())
                    # Add matches to the result list
                    for match in matches:
                        ip, port = match
                        dht_addresses.append((ip, int(port)))
        
        return dht_addresses
        
    except FileNotFoundError:
        log.error(f"Error: File '{filename}' not found")
        return []
    except Exception as e:
        log.error(f"Error occurred: {str(e)}")
        return []
    
class brDHT:
    
    def __init__(self, serverport:int, dhtid:int=None):
        self.serverport = serverport
        self.dhtServer = None
        self.asyncloop = asyncio.new_event_loop()
        self.bootstraplist = dht_file_read()
        self.shutdown = False
        self.dhtThread = None
        self.outbox = Queue(maxsize=2500)
        self.requestbox = Queue(maxsize=2500)
        self.requestresults = {}
        
        # Async specific stuff
        self.asyncloop.set_debug(True)
        if dhtid:
            self.dhtServer = Server(node_id=dhtid)
        else:
            self.dhtServer = Server()
            
        self.asyncloop.run_until_complete(self.dhtServer.listen(self.serverport))
        
        self.asyncloop.create_task(self.request_loop())
        if len(self.bootstraplist) == 0:
            log.info("No bootstrap nodes in list. Starting up alone...")
        else:
            log.info("Boot strapping DHT server...")
            self.asyncloop.run_until_complete(self.dhtServer.bootstrap(self.bootstraplist))
    
    async def getRequest(self, key):
        result = await self.dhtServer.get(key)
        return result
    
    def setRequest(self, key, data):       
        self.outbox.put((key, data))
 
    
    async def request_loop(self):
        log.info("Request processor for DHT has opened.")
        while self.shutdown == False:
            if self.requestbox.qsize() != 0:
                request = self.requestbox.get()
                result = await self.dhtServer.get(request)
                self.requestresults[request] = result
            
            elif self.outbox.qsize() != 0:
                key, data = self.outbox.get()
                await self.dhtServer.set(key, data)
                log.info(f"DHT: Sent key: {key}")
            else:
                await asyncio.sleep(1)
        log.info("Request processor is exiting due to shutdown signal.")