import rsa

class BrRSAImplement:
    """summary_ This is the default Backrooms Implementation of RSA objects.
    """
    
    def generateRSAKeys():
        """Generates Br Standard RSA keys with 4096 bits. The key length is generally considered safe though may be changed in the future.

        Returns:
            tuple (publicKey, privateKey): Specified 4096 bit key pair.
        """
        publicKey, privateKey = rsa.newkeys(4096)
        return publicKey, privateKey
    
        