import re
import asyncio
from queue import Queue
import socket
import time
from typing import Optional
import uuid
from kademlia.network import Server
from threading import Thread
import logging

from brCore.brEnclave import Enclave
from . import loggingfactory
from ..upnphelper import configureUPNP, removeUPNP

from ..brNodeNet.events import DHTRequest

log = loggingfactory.getDefaultLogger()


# Get a list of IP addresses and ports from bootstrapdht.txt
def dht_file_read():
    """Reads the bootstrapdht.txt file and extracts IP addresses and ports.

    Returns:
        list: A list of tuples containing (IP, port) pairs. Returns empty list on error.
    """
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
    """
    Kademlia DHT server manager for the Backrooms-net.

    Provides thread-safe interfaces for storing and retrieving data in a distributed
    hash table using enclave-backed storage. Handles bootstrapping, UPNP port mapping,
    and asynchronous request processing.
    """

    def __init__(self, enclaveStorage, serverport:int, dhtid:int=None):
        """
        Initialize and configure the DHT server.

        Sets up asyncio event loop, queues for requests, starts listening,
        and bootstraps if bootstrap nodes available.

        Note: Caller must start self.asyncThread.

        Args:
            enclaveStorage: Enclave storage instance.
            serverport (int): UDP port to bind.
            dhtid (int, optional): Specific node ID (defaults to random).
        """
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
        """Sets the bootstrap list for the DHT server and bootstraps asynchronously.

        Args:
            bootstraplist: List of bootstrap nodes.
        """
        log.info(f"Boot strapping DHT server with: {bootstraplist}")
        
        async def bootstrap_and_set():
            await self.dhtServer.bootstrap(bootstraplist)
            self.hasBootStrapped = True
        
        self.asyncloop.call_soon_threadsafe(lambda: self.asyncloop.create_task(bootstrap_and_set()))
        self.hasBootStrapped = True
    
    def set(self, key: str, value: any):
        """Fire-and-forget set. Returns immediately."""
        request = DHTRequest(key=key, value=value)
        self.outbox.put(request)                    # Reuse your existing queue


    def get(self, key: str, request_id: Optional[str] = None) -> Optional[str]:
        """
        Non-blocking GET.
        
        If request_id is provided, the result will come back as a DHT_RESPONSE event
        with that same request_id. This is the recommended way.
        
        Returns the result immediately only if it's already in the local cache.
        """
        if request_id is None:
            request_id = str(uuid.uuid4())
            
        request = DHTRequest(key=key, request_id=request_id)
        self.requestbox.put(request)                # Reuse your existing queue
        return None                                 # Caller should listen for event

    def shutdownServer(self):
        """
        Initiate shutdown of the DHT server.

        Sets shutdown flag and stops the event loop.

        Returns:
            List of known bootstrappable neighbor nodes.
        """
        self.shutdown = True
        self.asyncloop.stop()
        return self.dhtServer.bootstrappable_neighbors()
    
    async def request_loop(self):
        """
        Internal async loop for processing queued DHT operations.

        Processes gets from requestbox (stores in requestresults),
        sets from outbox, checks bootstrap status periodically.
        Exits on shutdown.
        """
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
                request:DHTRequest = self.outbox.get()
                await self.dhtServer.set(request.key, request.value)
                log.info(f"DHT: Sent key: {request.key}")
            else:
                await asyncio.sleep(1)
                
        log.info("Request processor is exiting due to shutdown signal.")

    def __runnerThread__(self):
        """
        Target function for the asyncio thread.

        Configures UPNP, runs the event loop indefinitely,
        removes UPNP mapping on exit.
        """
        if configureUPNP(self.serverport, "UDP", "Backrooms-net DHT Server") is not False:
            logging.info("UPNP configured for DHT.")
        self.asyncloop.run_forever()
        log.info("DHT Server Async Thread got shutdown signal.")
        removeUPNP(self.serverport, "UDP")
        
    def returnDHTLongID(self):
        """
        Get the long integer ID of the DHT node.

        Returns:
            int: The node ID as a long integer.
        """
        return self.dhtServer.node.long_id
    
    def returnDHTIP(self):
        """
        Get the IP address of the DHT node.

        Returns:
            The node's IP (str or bytes).
        """
        return self.dhtServer.node.ip

class brDHTQueryHelper:
    """
    Utility class for simplified DHT queries.

    Currently under development/placeholder.
    """

    def __init__(self, dhtserver:brDHT, enclave:Enclave):
        """
        Initialize the DHT query helper.

        Args:
            dhtserver (brDHT): The running DHT server instance.
            enclave (Enclave): Enclave for secure operations.
        """
        pass