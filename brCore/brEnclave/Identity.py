import rsa
import pickle
import math
import logging
import ctypes  # For secure_zero_memory

from . import brEnclaveLog  # Assuming this is your logger

class Identity:
    """Base Identity class for brNodes (RSA handling)."""

    def __init__(self) -> None:
        self.salt = None
        self.iv = None  # Both salt and iv are okay to have in clear memory
        self.publicKey = None
        self.privateKey = None
        self.islocked = False
        self.scuttled = False  # If we self destructed

    def getNewKeypair(self):
        """Creates a new RSA-4096 key pair ('Identity'). This method is time consuming.
        
        Values will be stored in self.publicKey and self.privateKey.
        """
        logging.info("Enclave Security -> Generating a new key pair for new identity. This may take a little while.")
        self.publicKey, self.privateKey = rsa.newkeys(4096)
        logging.info("Complete...")

    def chunkEncrypt(self, data_obj):
        """Encrypts any Python object into chunks using RSA and the current Identity.
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
        
        # 501 Bytes is the max bytes per chunk using RSA-4096 with PKCS1 padding. If key size changes, adjust this.
        # NOTE: Consider adding padding scheme explicit (e.g., PKCS1_OAEP) for better security; currently defaults to PKCS1-v1.5 which is less secure for new apps.
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
            pk = pickle.loads(self.decryptLocalData(self.privateKey, self.iv, self.salt))  # NOTE: Assumes decryptLocalData is imported from Encryption.py; we'll handle that in imports.
            clearData = rsa.decrypt(data_obj, pk)
            # pk = self.destroyData(pk)  # TODO: Fix this as per original note; currently commented to avoid breakage.
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
                self.salt = self.getNewSalt()  # NOTE: Assumes getNewSalt from Encryption.py.
            self.iv, self.privateKey = self.encryptLocalData(pickle.dumps(self.privateKey), self.salt)
            self.islocked = True
    
    def unlockIdentity(self):
        """Unlocks the Identity (Only RSA private key) in memory to be used by decryption methods.
        """
        if self.islocked:
            clearData = self.decryptLocalData(self.privateKey, self.iv, self.salt)
            self.privateKey = pickle.loads(clearData)
            clearData = self.destroyData(clearData)  # NOTE: destroyData needs to be moved/imported; I'll put it in Encryption.py as a util.
            self.islocked = False
        else:
            logging.error("Attempted to unlock Identity in the unlocked state!")

    @classmethod
    def newIdentFromPubImport(cls, keyData:str):
        newPub = rsa.PublicKey.load_pkcs1(keyData.encode('utf-8'))
        newIdent = cls()
        newIdent.publicKey = newPub
        return newIdent

    # NOTE: Added this as a class method for creating new identities, pulled from notrustvars.
    @classmethod
    def createIdentity(cls):
        """Creates a new RSA key pair and locks the Identity using AES. Method takes a while to run.

        Returns:
            Identity: Identity with new RSA key pair. After generation, Private key is locked.
        """
        logging.info("Creating new identity...")
        newIdentity = cls()
        newIdentity.getNewKeypair()
        newIdentity.lockIdentity()
        logging.info(f'New identity was created!')
        return newIdentity

# NOTE: You'll need to import functions like encryptLocalData, decryptLocalData, getNewSalt, destroyData from Encryption.py in your Enclave usage.