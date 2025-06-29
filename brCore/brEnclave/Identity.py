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