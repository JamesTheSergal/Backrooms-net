import re
import asyncio
from queue import Queue
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
    
    def __init__(self, serverport:int):
        self.serverport = serverport
        self.dhtServer = None
        self.asyncloop = None
        self.bootstraplist = dht_file_read()
        self.shutdown = False
        self.dhtThread = None
        self.outbox = Queue(maxsize=2500)
        self.requestbox = Queue(maxsize=2500)
    
    def start(self):
        self.dhtThread = Thread(target=brDHT.dht_thread, args=[self])
        self.dhtThread.start()
    
    def stop(self):
        self.shutdown = True
        log.info("Waiting for DHT thread to finish...")
        self.asyncloop.stop()
        self.dhtThread.join()
        log.info("DHT closed.")
    
    async def getRequest(self, key):
        result = await self.dhtServer.get(key)
        return result
    
    async def setRequest(self, key, data):
        result = await self.dhtServer.set(key, data)
        return result
    
    def dht_thread(self):
        log.info("DHT thread starting...")
        asyncio.loop
        loop = asyncio.get_event_loop()
        loop.set_debug(True)
        
        self.dhtServer = Server()
        loop.run_until_complete(self.dhtServer.listen(self.serverport))
        
        if len(self.bootstraplist) == 0:
            log.info("No bootstrap nodes in list. Starting up alone...")
        else:
            loop.run_until_complete(self.dhtServer.bootstrap(self.bootstraplist))
            
        try:
            log.info("Loop is running...")
            loop.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            self.dhtServer.stop()
            loop.close()
            log.info("DHT is shutdown.")