import rsa
from . import brEnclaveLog

class Identity:
    """Base Identity class for brNodes.
    """

    def __init__(self) -> None:
        self.salt = None
        self.iv = None # Both salt and iv are okay to have in clear memory
        self.publicKey = None
        self.privateKey = None
        self.islocked = False