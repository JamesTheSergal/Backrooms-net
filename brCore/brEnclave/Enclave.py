import logging
import threading

class Enclave:
    """Base class for a Backrooms Secure Data Object. v1.0.0 (BSDO)
    
    This class enables saving persistence data fully encrypted on disk and in memory, as well as security utilities to maintain system trust.
    """
    
    def __init__(self, enclaveName, newIdentity:bool = False) -> None:

        self.enclaveName = enclaveName
        
        # Get the logger from the package initilization
        self.logger = logging.getLogger("")

        # Main dictionary for storing data required to persist through a program restart, or to be encrypted while running.
        self.__data = {}

        # Thread lock for main data structure
        self.__threadLock = threading.Lock()

        # The Identity for this enclave
        self.assignedIdentity = None


