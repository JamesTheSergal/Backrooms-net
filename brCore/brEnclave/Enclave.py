import pickle
import threading
from pathlib import Path
from . import brEnclaveLog


class Enclave:
    """Base class for a Backrooms Secure Data Object. v1.0.0 (BSDO)
    
    This class enables saving persistence data fully encrypted on disk and in memory, as well as security utilities to maintain system trust.
    """
    
    class enclaveException(Exception):
        """Exception base class for the secure Enclave."""
        pass

    class enclaveDataIntegrityError(enclaveException):
        """Exception raised when data inside the enclave does not pass a hash check.
           This can be because of memory corruption, or a memory attack."""

        def __init__(self, data) -> None:
            self.message = "Data integrity error! Enclave is compromised! (Data Involved) ->"
            self.data = data
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"

    class enclaveIdentityError(enclaveException):
        """This exception is raised when there is an error attempting to deturmine the identity of this machine.
           There are several reasons this could happen. Most common hardware changes. (Network card)
           But this is to protect against the program operating on an unknown computer."""

        def __init__(self, data) -> None:
            self.message = "Identity Crisis! One or more identity checks run on this machine failed! (Data Involved) ->"
            self.data = data
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
        
    class enclaveSaveError(enclaveException):
        """This exception is raised while there is an error saving or moving enclave data."""

        def __init__(self, data) -> None:
            self.message = "Error occured while storing the Enclave! (Data Involved) ->"
            self.data = data
            super().__init__(self.message)

        def __str__(self):
            return f"{self.message}\n{pprint.pprint(self.data)}"
    
    class enclaveValueExists(enclaveException):
        """This exception is raised when there is already an existing key in the enclave."""

        def __init__(self, key) -> None:
            self.message = "Key already exists in enclave data ->"
            self.key = key
            super().__init__(self.key)

        def __str__(self):
            return f"{self.message} {self.key}"
        
    class enclaveValueDoesNotExist(enclaveException):
        """This exception is raised when there is not a key in the enclave that matches our requested value"""

        def __init__(self, key) -> None:
            self.message = "Key does not exist in enclave data ->"
            self.key = key
            super().__init__(self.key)

        def __str__(self):
            return f"{self.message} {self.key}"
    
    def __init__(self, enclaveName, newIdentity:bool = False) -> None:

        self.enclaveName = enclaveName
        
        # Get the logger from the package initilization
        self.logger = brEnclaveLog

        # Main dictionary for storing data required to persist through a program restart, or to be encrypted while running.
        self.__data = {}

        # Thread lock for main data structure
        self.__threadLock = threading.Lock()

        # The Identity for this enclave
        self.assignedIdentity = None
        
        # Salt for the Enclave. Used for at rest encryption.
        self.__salt = None
        
        # The Initilization vector used for at rest encryption.
        self.__vector = None
        
        self.target_enclave = Path(f'temp/{enclaveName}.encl')
        
        if self.target_enclave.is_file():
            if newIdentity:
                self.logger.error(f'Enclave with the name {enclaveName} already exists. We will not overwrite it.')
                raise Enclave.enclaveSaveError(f'ERROR: temp/{enclaveName}.encl <- Already exists!')
            else:
                self.loadEnclaveFile(f'temp/{enclaveName}.encl')
                self.assignedIdentity.publicKey = self.returnData("PublicKey")
        else:
            self.assignedIdentity = enclave.security.createIdentity()
            self.__salt = enclave.security.getNewSalt()
            self.insertData("PublicKey", self.assignedIdentity.publicKey)

    def loadEnclaveFile(self, location):
        target_ef = Path(location)
        if target_ef.is_file():
            self.logger.info(f'Enclave -> Loading {location=}')

            with open(self.dirpath + self.enclaveName + ".slt", "rb") as sf:
                self.__salt = sf.read()
        
            with open(self.dirpath + self.enclaveName + ".vector", "rb") as vf:
                self.__vector = vf.read()
        
            with open(self.dirpath + self.enclaveName + ".kf", "rb") as kf:
                self.assignedIdentity = enclave.security.identity()
                encryptedPair:tuple = pickle.load(kf)
                try:
                    self.assignedIdentity.privateKey = pickle.loads(enclave.security.decryptLocalData(encryptedPair[1], encryptedPair[0], self.__salt))
                except pickle.UnpicklingError:
                    self.logger.exception("Unable to decrypt enclave file! System changed/data corrupt/vector missing. Your data is not recoverable!", exc_info=True)
                    exit()
                self.assignedIdentity.lockIdentity()

            with open(location, 'rb') as ef:
                encryptedList = pickle.load(ef)
            clearData = b''
            for chunk in encryptedList:
                clearData += self.assignedIdentity.decryptChunk(chunk)

            clearData = enclave.security.decryptLocalData(clearData, self.__vector, self.__salt)

            self.__data = pickle.loads(clearData)
            self.logger.debug(f'Enclave has {len(self.__data)} entries.')
            return True
        else:
            self.logger.error(f'Enclave -> File not found! {location=}')
            return False
        