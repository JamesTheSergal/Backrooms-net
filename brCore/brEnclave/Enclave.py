import hashlib
import os
import pickle
import threading
from pathlib import Path
import logging
import pprint

from .Encryption import (encryptLocalData, decryptLocalData, getNewSalt, derive_key, destroyData, getMachineSHA256)
from .Identity import Identity
from . import brEnclaveLog  # Your logger

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
    
    def __init__(self, enclaveName, pathtouse:str=None, newIdentity:bool = False) -> None:
        """
        Initialize the Enclave instance.
        
        Args:
            enclaveName (str): The name of the enclave.
            pathtouse (str, optional): The directory path to use for storing enclave files. Defaults to 'temp/'.
            newIdentity (bool, optional): Whether to create a new identity even if the enclave file exists. Defaults to False.
        """
        self.enclaveName = enclaveName
        
        # Get the logger from the package initilization
        self.logger = brEnclaveLog

        # Main dictionary for storing data required to persist through a program restart, or to be encrypted while running.
        self.__data = {}

        # Thread lock for main data structure
        self.__threadLock = threading.Lock()

        # Hashes for unencrypted data (key:shaHash)
        self.__dataHashes = {}

        # Key values associated with hashes for reverse lookup. (hash:key)
        self.__reverseHash = {}

        # Encrypted data hashes. If an entry was encrypted, save the hash of the encrypted data. This can prevent injection attacks.
        # (AKA, we can check if the data was tampered with before we decrypt it. Prevents sophisticated attacks.)
        self.__encryptedHash = {} #(key:hash)

        # The Identity for this enclave
        self.assignedIdentity = None
        
        # Salt for the Enclave. Used for at rest encryption.
        self.__salt = None
        
        # The Initilization vector used for at rest encryption.
        self.__vector = None
        
        # Directory setup
        if pathtouse is None:
            self.dirpath = 'temp/'  # NOTE: Made this configurable? E.g., via env var for production (avoid 'temp' in shared envs).
            tempdir = Path(self.dirpath)
            self.target_enclave = Path(f'{self.dirpath}{enclaveName}.encl')
        else:
            self.dirpath = pathtouse
            tempdir = Path(self.dirpath)
            self.target_enclave = Path(f'{self.dirpath}{enclaveName}.encl')
            
        if not tempdir.is_dir():
            try:
                os.mkdir(self.dirpath)
            except OSError:
                self.logger.error("Couldn't create temp directory!", exc_info=True)
            except Exception as e:
                self.logger.error("Unknown error when creating temp directory!", exc_info=True)

        if self.target_enclave.is_file():
            if newIdentity:
                self.logger.error(f'Enclave with the name {enclaveName} already exists. We will not overwrite it.')
                raise Enclave.enclaveSaveError(f'ERROR: {self.target_enclave} <- Already exists!')
            else:
                self.loadEnclaveFile(self.target_enclave)
                self.assignedIdentity.publicKey = self.returnData("PublicKey")
        else:
            self.assignedIdentity = Identity.createIdentity()
            self.__salt = getNewSalt()
            self.insertData("PublicKey", self.assignedIdentity.publicKey)

    def __verifyDataHash__(self, key=None, hash=None):
        """
        Verify the integrity of data associated with a key or find the key by hash.
        
        Args:
            key (str, optional): The key to verify.
            hash (str, optional): The hash to find the associated key.
        
        Returns:
            bool or str or None: True if key exists and hash matches, False if key not in hashes,
                the key if hash found, None otherwise.
        
        Raises:
            enclaveDataIntegrityError: If hash mismatch for the key.
        """
        with self.__threadLock:
            if key is not None:
                if key in self.__dataHashes:
                    current_hash = hashlib.sha256(pickle.dumps(self.__data[key])).hexdigest()
                    if current_hash != self.__dataHashes[key]:
                        raise Enclave.enclaveDataIntegrityError(f"Hash mismatch for key: {key}")
                    return True
                else:
                    return False
            elif hash is not None:
                if hash in self.__reverseHash:
                    return self.__reverseHash[hash]
                else:
                    return None

    def loadEnclaveFile(self, location):
        """
        Load the enclave data from the specified file location.
        
        Args:
            location (str): The path to the enclave file.
        
        Returns:
            bool: True if loaded successfully, False if file not found.
        
        Raises:
            enclaveIdentityError: If decryption fails.
        """
        target_ef = Path(location)
        if target_ef.is_file():
            self.logger.info(f'Enclave -> Loading {location=}')

            with open(self.dirpath + self.enclaveName + ".slt", "rb") as sf:
                self.__salt = sf.read()
        
            with open(self.dirpath + self.enclaveName + ".vector", "rb") as vf:
                self.__vector = vf.read()
        
            with open(self.dirpath + self.enclaveName + ".kf", "rb") as kf:
                self.assignedIdentity = Identity()
                encryptedPair:tuple = pickle.load(kf)
                try:
                    self.logger.debug("Attempting to decrypt and load key file...")
                    self.assignedIdentity.privateKey = pickle.loads(decryptLocalData(encryptedPair[1], encryptedPair[0], self.__salt))
                except pickle.UnpicklingError:
                    self.logger.exception("Unable to decrypt enclave file! System changed/data corrupt/vector missing. Your data is not recoverable!", exc_info=True)
                    raise Enclave.enclaveIdentityError("Decryption failed")  # NOTE: Changed from exit() to raise, for better library behavior.
                self.logger.debug("Success, locking data...")
                self.assignedIdentity.lockIdentity()

            self.logger.debug("Reading and decrypting Enclave file...")
            with open(location, 'rb') as ef:
                encryptedList = pickle.load(ef)
            clearData = b''
            for chunk in encryptedList:
                clearData += self.assignedIdentity.decryptChunk(chunk)

            self.logger.debug("Reading and decrypting Enclave object data...")
            clearData = decryptLocalData(clearData, self.__vector, self.__salt)

            self.__data = pickle.loads(clearData)
            self.logger.debug(f'Enclave has {len(self.__data)} entries.')
            # NOTE: Add integrity check here post-load? E.g., for each key, compute hash and store in __dataHashes if not present.
            return True
        else:
            self.logger.error(f'Enclave -> File not found! {location=}')
            return False
        
    def saveEnclaveFile(self, overwrite=False):
        """
        Save the enclave data to the target file.
        
        Args:
            overwrite (bool, optional): Whether to overwrite existing file. Defaults to False.
        
        Returns:
            bool: True if saved, False if file exists and overwrite is False.
        
        Raises:
            enclaveException: If identity is not locked.
        """
        if self.target_enclave.is_file() and not overwrite:
            self.logger.error(f'Warning -> Enclave already exists! Cannot overwrite Enclave! {self.target_enclave=}')
            return False
        else:
            self.logger.info(f'Enclave -> Saving to {self.target_enclave}')
            self.logger.debug(f'Enclave has {len(self.__data)} entries.')

        toEncryptBytes = pickle.dumps(self.__data)
        self.__vector, aesEncryptedData = encryptLocalData(toEncryptBytes, self.__salt)  # NOTE: Updated to store vector here if new.

        encryptedData = self.assignedIdentity.chunkEncrypt(aesEncryptedData)
        with open(self.target_enclave, 'wb') as ef:
            pickle.dump(encryptedData, ef)

        with open(self.dirpath + self.enclaveName + ".slt", "wb") as sf:
            sf.write(self.__salt)
        
        with open(self.dirpath + self.enclaveName + ".vector", "wb") as vf:
            vf.write(self.__vector)
        
        with open(self.dirpath + self.enclaveName + ".kf", "wb") as kf:
            if self.assignedIdentity.islocked:
                self.assignedIdentity.unlockIdentity()
                ivkeypair = encryptLocalData(pickle.dumps(self.assignedIdentity.privateKey), self.__salt)
                self.assignedIdentity.lockIdentity()
                toStoreBytes = pickle.dumps(ivkeypair)
            else:
                self.logger.warning("Identity was not locked before storage!")
                raise Enclave.enclaveException("Identity not locked")  # NOTE: Enforce locking.
            kf.write(toStoreBytes)

        # NOTE: Consider adding file permissions here (e.g., os.chmod(self.target_enclave, 0o600)) for security.
        return True
    
    def isEncKey(self, key):
        """
        Check if the given key exists in the enclave data.
        
        Args:
            key: The key to check.
        
        Returns:
            bool: True if key exists, False otherwise.
        """
        with self.__threadLock:
            return key in self.__data.keys()
            
    def updateEntry(self, key, obj, create=True):
        """
        Update the value for an existing key or create a new entry if create is True.
        
        Args:
            key: The key to update.
            obj: The new object to store.
            create (bool, optional): Whether to create if key doesn't exist. Defaults to True.
        
        Returns:
            bool: True if updated.
        
        Raises:
            enclaveValueDoesNotExist: If key doesn't exist and create is False.
        """
        if self.isEncKey(key) or create:
            with self.__threadLock:
                self.__data[key] = obj
                # Update hash for integrity
                data_hash = hashlib.sha256(pickle.dumps(obj)).hexdigest()
                self.__dataHashes[key] = data_hash
                self.__reverseHash[data_hash] = key
        else:
            raise Enclave.enclaveValueDoesNotExist(key)
        return True
            
    def insertData(self, key, obj):
        """
        Insert a new key-value pair into the enclave data.
        
        Args:
            key: The key for the data.
            obj: The object to store.
        
        Returns:
            bool: True if inserted.
        
        Raises:
            enclaveValueExists: If key already exists.
        """
        if not self.isEncKey(key):
            with self.__threadLock:
                self.__data[key] = obj
                # Add hash on insert
                data_hash = hashlib.sha256(pickle.dumps(obj)).hexdigest()
                self.__dataHashes[key] = data_hash
                self.__reverseHash[data_hash] = key
                return True
        else:
            raise Enclave.enclaveValueExists(key)
    
    def returnData(self, key):
        """
        Retrieve the data associated with the given key.
        
        Args:
            key: The key to retrieve.
        
        Returns:
            The stored object.
        
        Raises:
            enclaveValueDoesNotExist: If key doesn't exist.
        """
        if self.isEncKey(key):
            self.__verifyDataHash__(key)  # NOTE: Call verification on read for tamper detection.
            return self.__data[key]
        else:
            raise Enclave.enclaveValueDoesNotExist(key)
        
    def deleteKey(self, key):
        """
        Delete the key-value pair from the enclave data.
        
        Args:
            key: The key to delete.
        
        Raises:
            enclaveValueDoesNotExist: If key doesn't exist.
        """
        self.logger.warning(f"Enclave delete key was called on key:{key} (Doesn't happen that often)")
        if self.isEncKey(key):
            with self.__threadLock:
                del self.__data[key]
                data_hash = self.__dataHashes[key]
                del self.__dataHashes[key]
                del self.__reverseHash[data_hash]

# NOTE: Todo: Implement encryptedHash usage (e.g., hash encrypted chunks and check before decrypt). Also, consider adding deleteEntry method.

    # Specific tools
    
    # This method is probably pretty expensive in terms of performance.
    def appendOntoList(self, key, obj):
        """
        Append an object to the list associated with the key.
        
        Args:
            key: The key of the list.
            obj: The object to append.
        
        If the key doesn't exist, creates a new list with the object.
        """
        if self.isEncKey(key):
            existing_arr:list = self.returnData(key)
            existing_arr.append(obj)
            self.updateEntry(key, existing_arr)
        else:
            self.insertData(key, [obj])
    
    def removeFrromList(self, key, obj):
        """
        Remove an object from the list associated with the key by index.
        
        Args:
            key: The key of the list.
            obj (int): The index of the object to remove.
        
        Raises:
            enclaveValueDoesNotExist: If key doesn't exist.
        """
        if self.isEncKey(key):
            existing_arr:list = self.returnData(key)
            existing_arr.pop(obj)
            self.updateEntry(key, existing_arr)
        else:
            raise self.enclaveValueDoesNotExist(key)
            
            