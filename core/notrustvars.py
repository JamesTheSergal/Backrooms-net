import hashlib
import os
import platform
import math
import uuid
import cryptography
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import threading
import rsa
import logging
import pickle
import pprint
import ctypes
from pathlib import Path

class enclave:
    """Base class for a Backrooms Secure Data Object. (BSDO)
    
    This class enables saving persistence data fully encrypted on disk and in memory, as well as security utilities to maintain system trust.

    Features:
        enclave.security: Has security related methods for encrypting/decrypting data securely, deturmining machine identity, derive encryption keys.
        enclave.security.identity: Strictly deals with the RSA keys required for network identity. Required to decrypt/encrypt RSA chunks.
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

    class security:
        """Base security class for Backrooms Enclaves.
        """

        class identity:
            """Base Identity class for RSA encryption.
            """

            def __init__(self) -> None:
                self.salt = None
                self.iv = None # Both salt and iv are okay to have in clear memory
                self.publicKey = None
                self.privateKey = None
                self.islocked = False
                self.scuttled = False # If we self destructed
            
            def getNewKeypair(self):
                """Creates a new RSA-4096 key pair ("Identity"). This method is time consuming.
                
                Values will be stored in self.publicKey and self.privateKey.
                """
                
                logging.info("Enclave Security -> Generating a new key pair for new identity. This may take a little while.")
                self.publicKey, self.privateKey = rsa.newkeys(4096)
                logging.info("Complete...")

            def chunkEncrypt(self, data_obj):
                """Encrypts any Python object into chunks using RSA and the current Idenity.
                Note: If no key pair has been generated or loaded, the encryption will fail.

                Args:
                    data_obj (Any): Can take any Python object to encrypt.

                Returns:
                    list: A list of encrypted chunks. Each chunk is the max size RSA-4096 will allow.
                """
                logging.debug("Encrypting object...")

                if type(data_obj) is not bytes:
                    data = pickle.dumps(data_obj)
                else:
                    data = data_obj

                logging.debug(f'Encrypting {len(data)} bytes... (About {math.ceil(len(data)/501)} chunk(s)...)')
                chunkList = []
                outputLen = 0
                
                # 501 Bytes is the max bytes per chunk using RSA-4096. If the key size is changed, this needs to change too.
                for i in range(0, len(data), 501):
                    slice_bytes = data[i:i + 501]
                    encrypted = rsa.encrypt(slice_bytes, self.publicKey)
                    outputLen += len(encrypted)
                    chunkList.append(encrypted)
        
                logging.debug(f'Completed encryption. Resulting size {outputLen=}')
                return chunkList 
    
            def decryptChunk(self, data_obj: bytes, borrow:bool=True):
                """Decrypts one chunk of RSA data using the current Identity.

                Args:
                    data_obj (bytes): The RSA chunk in bytes that we are decrypting.
                    borrow (bool): Makes decrypting the local private key and using it referenced locally rather than decrypting and storing the key in the same memory reference.

                Returns:
                    Bytes: Clear unencrypted data
                """
                if borrow is True:
                    pk = pickle.loads(enclave.security.decryptLocalData(self.privateKey, self.iv, self.salt))
                    clearData = rsa.decrypt(data_obj, pk)
                    #pk = enclave.security.destroyData(pk) # TODO: Fix this
                    return clearData
                else:
                    if self.islocked:
                        self.unlockIdentity()
                        clearData = rsa.decrypt(data_obj, self.privateKey)
                        self.lockIdentity()
                        return clearData

            def lockIdentity(self):
                """Locks the Identity (Only RSA private key) in memory using AES to harden against attacks.
                
                *Why should we do this?* - 
                While it is true that this will not prevent the identity (RSA Key pair) from being found in a memory attack
                It should certainly make it harder if the Private key is encrypted in memory between transactions.
                Therefore, calling lock, and unlock methods are advised whenever possible.
                """
                if self.islocked:
                    logging.error("Attempted to lock Identity while it is in the locked state!")
                else:
                    if self.salt == None:
                        self.salt = enclave.security.getNewSalt()
                    self.iv, self.privateKey = enclave.security.encryptLocalData(pickle.dumps(self.privateKey), self.salt)
                    self.islocked = True
            
            def unlockIdentity(self):
                """Unlocks the Identity (Only RSA private key) in memory to be used by decryption methods.
                """
                if self.islocked:
                    clearData = enclave.security.decryptLocalData(self.privateKey, self.iv, self.salt)
                    self.privateKey = pickle.loads(clearData)
                    clearData = enclave.security.destroyData(clearData)
                    self.islocked = False
                else:
                    logging.error("Attempted to unlock Identity in the unlocked state!")

            def newIdentFromPubImport(keyData:str):
                newPub = rsa.PublicKey.load_pkcs1(keyData.encode('utf-8'))
                newIdent = enclave.security.identity()
                newIdent.publicKey = newPub
                return newIdent


        def __getMachineIdentity__():
            """Generates a unique identifier for the current machine using the (MAC-SystemType-SystemDomainName)
            This is used to verify the system's identity and derive a decryption key.
            
            Returns:
                tuple: (identifier, idHash) String identifying the current machine and a SHA hash of that identifier.
            """
            identifier = f'{uuid.getnode()}-{platform.system()}-{platform.node()}' #TODO: Make a more robust way of generating an Identifier. MAC can be found by ARP packet not behind NAT.
            idHash = hashlib.sha256(identifier.encode("utf-8"))
            return (identifier, idHash)

        def getNewSalt():
            """Generates a 16-Byte (128-bit) random salt used in AES encryption.

            Returns:
                bytes: Salt generated by the system's OS.
            """
            return os.urandom(16) # 128-bit salt

        def derive_key(salt):
            """This method uses the system's identity to derive an AES encryption key.

            Args:
                salt (Bytes): Random bytes used in the encryption of AES data.

            Returns:
                Bytes: The derived AES key in Bytes.
            """
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            identifier, idHash = enclave.security.__getMachineIdentity__()
            machineDerivedKey = kdf.derive(identifier.encode("utf-8"))
            return machineDerivedKey

        def getMachineSHA256():
            identifier, idHash = enclave.security.__getMachineIdentity__()
            return idHash

        def encryptLocalData(dataObj, salt):
            """Uses AES to encrypt data using the System's unique key.

            Args:
                dataObj (Bytes): Bytes to be encrypted.
                salt (Bytes): Unique 16 bytes used for encryption.

            Returns:
                tuple: (iv, encrypted_data) Initilization Vector and the data. Store the IV since it is needed for decryption.
            """
            iv = os.urandom(16)
            machineKey = enclave.security.derive_key(salt)
            cipher = Cipher(algorithms.AES(machineKey), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(dataObj) + encryptor.finalize()
            return iv, encrypted_data
        
        def decryptLocalData(dataObj, initVector, salt):
            """Uses AES to decrypt data using the original initilization vector and salt.

            Args:
                dataObj (bytes): AES encrypted data
                initVector (bytes): Unique 16 bytes used for encryption.
                salt (bytes): Unique 16 bytes used for encryption.

            Returns:
                bytes: Decrypted bytes
            """
            machineDerivedKey = enclave.security.derive_key(salt)
            cipher = Cipher(algorithms.AES(machineDerivedKey), modes.CFB(initVector), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(dataObj) + decryptor.finalize()
            machineDerivedKey = enclave.security.destroyData(machineDerivedKey)
            return decrypted_data

        def createIdentity():
            """Creates a new RSA key pair and locks the Identity using AES. Method takes a while to run.

            Returns:
                enclave.security.identity: Identity with new RSA key pair. After generation, Private key is locked.
            """
            logging.info("Creating new identity...")
            newIdentity = enclave.security.identity()
            newIdentity.getNewKeypair()
            newIdentity.lockIdentity()
            logging.info(f'New identity was created!')
            return newIdentity

        def secure_zero_memory(data):
            """Overwrite the memory of the given data with Zeros."""
            size = len(data)
            ctypes.memset(id(data) + ctypes.sizeof(ctypes.c_size_t) * 2, 0, size)

        def destroyData(referenceToData, varName:str=None):
            """Method overwrites your variable with zeros in memory to protect against memory attacks.

            Args:
                referenceToData (Any): Any Python object
                varName (Str, None): Name of variable used for debug purposes. Otherwise non-specific. Defaults to None.

            Returns:
                Bytes: Bytes to overwrite the current variable in memory.
            """
            if varName is not None:
                logging.debug(f'Destroying reference to "{varName}" in memory with zeros...')
            else:
                logging.debug(f'Destroying reference to a variable in memory with zeros...')

            if isinstance(referenceToData, bytes):
                return b'\x00' * len(referenceToData)
            elif isinstance(referenceToData, rsa.PrivateKey):
                enclave.security.secure_zero_memory(referenceToData.d)
                enclave.security.secure_zero_memory(referenceToData.p)
                enclave.security.secure_zero_memory(referenceToData.q)
                enclave.security.secure_zero_memory(referenceToData.exp1)
                enclave.security.secure_zero_memory(referenceToData.exp2)
                enclave.security.secure_zero_memory(referenceToData.coef)
                return None
    
    class listInterface:
        
        def __init__(self, internalReference:list, threadLockObject:threading.Lock) -> None:
            self.data:list = internalReference
            self.thrLock:threading.Lock = threadLockObject
       
    def __init__(self, enclaveName, newIdentity:bool = False) -> None:

        self.enclaveName = enclaveName

        # Main dictionary for storing data required to persist through a program restart, or to be encrypted while running.
        self.__data = {}

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

        # The generated salt we used. This is safe to store in memory
        self.__salt = None

        # The Initilization Vector used to encrypt the enclave file
        self.__vector = None

        # Check for temp directory
        tempdir = Path("temp/")
        self.target_enclave = Path(f'temp/{enclaveName}.encl')
        self.dirpath = f'temp/'

        if tempdir.is_dir():
            pass
        else:
            try:
                os.mkdir("temp/")
            except OSError:
                logging.error("Couldn't create temp directory!", exc_info=True)
            except Exception as e:
                logging.error("Unknown error when creating temp directory!", exc_info=True)

        if self.target_enclave.is_file():
            if newIdentity:
                logging.error(f'Enclave with the name {enclaveName} already exists. We will not overwrite it.')
                raise enclave.enclaveSaveError(f'ERROR: temp/{enclaveName}.encl <- Already exists!')
            else:
                self.loadEnclaveFile(f'temp/{enclaveName}.encl')
                self.assignedIdentity.publicKey = self.returnData("PublicKey")
        else:
            self.assignedIdentity = enclave.security.createIdentity()
            self.__salt = enclave.security.getNewSalt()
            self.insertData("PublicKey", self.assignedIdentity.publicKey)

    def __verifyDataHash__(self, key=None, hash=None):
        if key is not None:
            if key in self.__dataHashes.keys():
                reverse = self.__dataHashes
        
    def loadEnclaveFile(self, location):
        target_ef = Path(location)
        if target_ef.is_file():
            logging.info(f'Enclave -> Loading {location=}')

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
                    logging.exception("Unable to decrypt enclave file! System changed/data corrupt/vector missing. Your data is not recoverable!", exc_info=True)
                    exit()
                self.assignedIdentity.lockIdentity()

            with open(location, 'rb') as ef:
                encryptedList = pickle.load(ef)
            clearData = b''
            for chunk in encryptedList:
                clearData += self.assignedIdentity.decryptChunk(chunk)

            clearData = enclave.security.decryptLocalData(clearData, self.__vector, self.__salt)

            self.__data = pickle.loads(clearData)
            logging.debug(f'Enclave has {len(self.__data)} entries.')
            return True
        else:
            logging.error(f'Enclave -> File not found! {location=}')
            return False
        
    def saveEnclaveFile(self, overwrite=False):
        if self.target_enclave.is_file() and overwrite == False:
            logging.error(f'Warning -> Enclave already exists! Cannot overwrite Enclave! {self.target_enclave=}')
            return False
        else:
            logging.info(f'Enclave -> Saving to {self.target_enclave}')
            logging.debug(f'Enclave has {len(self.__data)} entries.')

        toEncryptBytes = pickle.dumps(self.__data)
        vector, aesEncryptedData = enclave.security.encryptLocalData(toEncryptBytes, self.__salt)

        encryptedData = self.assignedIdentity.chunkEncrypt(aesEncryptedData)
        with open(self.target_enclave, 'wb') as ef:
            pickle.dump(encryptedData, ef)

        with open(self.dirpath + self.enclaveName + ".slt", "wb") as sf:
            sf.write(self.__salt)
        
        with open(self.dirpath + self.enclaveName + ".vector", "wb") as vf:
            vf.write(vector)
        
        with open(self.dirpath + self.enclaveName + ".kf", "wb") as kf:
            if self.assignedIdentity.islocked:
                self.assignedIdentity.unlockIdentity()
                ivkeypair = enclave.security.encryptLocalData(pickle.dumps(self.assignedIdentity.privateKey), self.__salt)
                self.assignedIdentity.lockIdentity()
                toStoreBytes = pickle.dumps(ivkeypair)
            else:
                logging.warning("Identity was not locked before storage!")
                raise enclave.enclaveException() #TODO: Handle this differently
            kf.write(toStoreBytes)

        return True
    
    def isEncKey(self, key):
        with self.__threadLock:
            if key in self.__data.keys():
                return True
            else:
                return False
            
    def updateEntry(self, key, obj, create=True):
        if self.isEncKey(key) or create==True:
            with self.__threadLock:
                self.__data[key] = obj
        else:
            raise enclave.enclaveValueDoesNotExist(key)
        return True
            
    def insertData(self, key, obj):
        if not self.isEncKey(key):
            with self.__threadLock:
                self.__data[key] = obj
            return True
        else:
            raise enclave.enclaveValueExists(key)
    
    def returnData(self, key):
        if self.isEncKey(key):
            with self.__threadLock:
                requested = self.__data[key]
        else:
            raise enclave.enclaveValueDoesNotExist(key)
        return requested
    
    def createIfNotExist(self, key, data):
        if not self.isEncKey(key):
            with self.__threadLock:
                self.__data[key] = data
            return False
        else:
            return True
            
    
    def createListInterface(self, key, create:bool=True):
        if self.isEncKey(key):
            if isinstance(self.__data[key], list):
                return self.listInterface(self.__data[key], self.__threadLock)
            else:
                raise enclave.enclaveValueDoesNotExist(key) # TODO: change this later
        else:
            if create:
                self.__data[key] = []
                return self.listInterface(self.__data[key, self.__threadLock])
            else:
                raise enclave.enclaveValueDoesNotExist(key)
