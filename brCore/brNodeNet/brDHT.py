import re
import asyncio
from queue import Queue
import socket
import time
from kademlia.network import Server
from threading import Thread
import logging

from brCore.brEnclave import Enclave
from . import loggingfactory
from ..upnphelper import configureUPNP, removeUPNP

log = loggingfactory.getDefaultLogger()


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
    
    def __init__(self, enclaveStorage, serverport:int, dhtid:int=None):
        self.serverport = serverport
        self.dhtServer = None
        self.asyncloop = asyncio.new_event_loop()
        self.asyncThread = Thread(name="DHT Server Thread", target=self.__runnerThread__, args=[])
        self.bootstraplist = dht_file_read()
        self.shutdown = False
        self.dhtThread = None
        self.outbox = Queue(maxsize=2500)
        self.requestbox = Queue(maxsize=2500)
        self.hasBootStrapped = False
        self.requestresults = {}
        
        # Async specific stuff
        self.asyncloop.set_debug(True)
        if dhtid:
            self.dhtServer = Server(node_id=dhtid, storage=enclaveStorage)
        else:
            self.dhtServer = Server(storage=enclaveStorage)
            
            
        self.asyncloop.run_until_complete(self.dhtServer.listen(self.serverport))
        
        self.asyncloop.create_task(self.request_loop())
        if len(self.bootstraplist) == 0:
            log.info("No bootstrap nodes in text list. Starting up alone...")
        else:
            log.info("Boot strapping DHT server...")
            self.asyncloop.run_until_complete(self.dhtServer.bootstrap(self.bootstraplist))
            self.hasBootStrapped = True
    
    def setBootstrapList(self, bootstraplist):
        log.info(f"Boot strapping DHT server with: {bootstraplist}")
        
        async def bootstrap_and_set():
            await self.dhtServer.bootstrap(bootstraplist)
            self.hasBootStrapped = True
        
        self.asyncloop.call_soon_threadsafe(lambda: self.asyncloop.create_task(bootstrap_and_set()))
        self.hasBootStrapped = True
    
    async def getRequest(self, key):
        result = await self.dhtServer.get(key)
        return result
    
    def setRequest(self, key, data):       
        self.outbox.put((key, data))

    def shutdownServer(self):
        self.shutdown = True
        self.asyncloop.stop()
        return self.dhtServer.bootstrappable_neighbors()
    
    async def request_loop(self):
        log.info("Request processor for DHT has opened.")
        while self.shutdown == False:
            if not self.hasBootStrapped:
                neighbors = self.dhtServer.protocol.router.find_neighbors(self.dhtServer.node)
                if neighbors:
                    self.hasBootStrapped = True
                    log.info("DHT server now has neighbors; marking as bootstrapped.")
            
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

    def __runnerThread__(self):
        if configureUPNP(self.serverport, "UDP", "Backrooms-net DHT Server") is not False:
            logging.info("UPNP configured for DHT.")
        self.asyncloop.run_forever()
        log.info("DHT Server Async Thread got shutdown signal.")
        removeUPNP(self.serverport, "UDP")
        
    def returnDHTLongID(self):
        return self.dhtServer.node.long_id
    
    def returnDHTIP(self):
        return self.dhtServer.node.ip

class brDHTQueryHelper:
    
    def __init__(self, dhtserver:brDHT, enclave:Enclave):
        pass