import os
import rsa

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#
# General tools
#________

def generate128Bits():
    return os.urandom(16)

def generate256Bits():
    return os.urandom(32)

def generate512Bits():
    return os.urandom(64)

#
# RSA Tools and tricks
#________

def generateRSAKeys():
    """Generates Br Standard RSA keys with 4096 bits. The key length is generally considered safe though may be changed in the future.

    Returns:
        tuple (publicKey, privateKey): Specified 4096 bit key pair.
    """
    publicKey, privateKey = rsa.newkeys(4096)
    return publicKey, privateKey
    
    
#
# AES Tools and tricks
#________

def deriveKeyFromBytes(salt:bytes, keyBytes:bytes):
    """This method uses bytes (similar to a password) to derive an AES encryption key.

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
    encKey = kdf.derive(keyBytes)
    return encKey

def encryptWithAES(dataObj: bytes, key:bytes, salt:bytes, iv:bytes = None):
    """This method uses AES to encrypt data using the provided salt, and iv.

    Args:
        dataObj (Bytes): Bytes to be encrypted.
        key (bytes): AES Encryption key.
        salt (Bytes): Unique 16 bytes used for encryption.
        iv (Bytes):Unique 16 bytes used for encryption.

    Returns:
        tuple: (iv, encrypted_data) Initilization Vector and the data. Store the IV since it is needed for decryption.
    """
    
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(dataObj) + encryptor.finalize()
    return encrypted_data

def decryptWithAES(dataObj: bytes, keyBytes: bytes, iv: bytes, salt: bytes):
    
    cipher = Cipher(algorithms.AES(keyBytes), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(dataObj) + decryptor.finalize()
    return decrypted_data

    
        