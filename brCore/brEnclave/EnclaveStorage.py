import operator
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from itertools import takewhile
from .Enclave import Enclave  # Assuming relative import from brEnclave package
from kademlia.storage import IStorage  # Import the interface
from . import brEnclaveLog  # Your logger

class EnclaveStorage(IStorage):
    def __init__(self, enclave: Enclave, ttl=604800):
        """
        Persistent storage using the Enclave for DHT data.
        By default, max age is a week.
        """
        self.enclave = enclave
        self.ttl = ttl
        self.storage_key = "dht_storage"  # Key in enclave to store the data dict
        try:
            self.data = self.enclave.returnData(self.storage_key)
            if not isinstance(self.data, OrderedDict):
                self.data = OrderedDict(self.data)
        except Enclave.enclaveValueDoesNotExist:
            self.data = OrderedDict()
            self._save()  # Save initial empty dict

    def _save(self):
        """Save the current data to the enclave."""
        self.enclave.updateEntry(self.storage_key, self.data, create=True)
        brEnclaveLog.info("DHT saved data to Enclave")

    def __setitem__(self, key, value):
        if key in self.data:
            del self.data[key]
        self.data[key] = (time.monotonic(), value)
        self.cull()
        self._save()
        brEnclaveLog.info(f"DHT saved {key} to Enclave")

    def cull(self):
        for _, _ in self.iter_older_than(self.ttl):
            self.data.popitem(last=False)
        self._save()

    def get(self, key, default=None):
        self.cull()
        brEnclaveLog.info(f"DHT looking for {key} in Enclave")
        if key in self.data:
            brEnclaveLog.info(f"DHT found {key} in Enclave")
            return self[key]
        brEnclaveLog.info(f"DHT did not find {key} in Enclave")
        return default

    def __getitem__(self, key):
        self.cull()
        return self.data[key][1]

    def __repr__(self):
        self.cull()
        return repr(self.data)

    def iter_older_than(self, seconds_old):
        min_birthday = time.monotonic() - seconds_old
        zipped = self._triple_iter()
        matches = takewhile(lambda r: min_birthday >= r[1], zipped)
        return list(map(operator.itemgetter(0, 2), matches))

    def _triple_iter(self):
        ikeys = self.data.keys()
        ibirthday = map(operator.itemgetter(0), self.data.values())
        ivalues = map(operator.itemgetter(1), self.data.values())
        return zip(ikeys, ibirthday, ivalues)

    def __iter__(self):
        self.cull()
        ikeys = self.data.keys()
        ivalues = map(operator.itemgetter(1), self.data.values())
        return zip(ikeys, ivalues)