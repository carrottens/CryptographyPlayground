# ***********
# Task 2
# ***********
# Users A and B use the Diffie-Hellman (DH) key exchange protocol to share a secret key and start encrypting data. 
# You can assume that users A and B agreed on some DH parameters and calculated their private keys. 
# You are given the private keys for users A and B are given.

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

def RepeatingXOREncrypt(key, string):
    # Convert the key into bytes
    keyBytes = bytes(key)

    # XOR the key in byte format with string in byte format
    result = bytes([string[i]^keyBytes[i%len(keyBytes)] for i in range(len(string))])

    # Return the XOR value in bytes
    return result

# Information on the type of variables:
# [A_Private_Key, B_Private_Key] = PEM format
# [PlainText] = bytes
# [sharedKey, cipher] = bytes 
def DHandEncrypt(A_Private_Key, B_Private_Key, PlainText):

    # Convert PEM keys into key objects
    privateKeyA = serialization.load_pem_private_key(A_Private_Key, password=None)
    privateKeyB = serialization.load_pem_private_key(B_Private_Key, password=None)

    # Key exchange
    sharedKey = privateKeyA.exchange(privateKeyB.public_key())

    # Key derivation
    derivedKey = HKDF(algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data').derive(sharedKey)

    # Encrypt by XORing derived key with the PlainText
    cipher = RepeatingXOREncrypt(derivedKey, PlainText)
    
    return derivedKey, cipher

if __name__ == "__main__":

    #User A's and B's private keys (in PEM no password)
    #keyA = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBm\nZK4qUqvU6WaPy4fNG9oWIXchxzztxmA7p9BFXbMzn3rHcW84SDwTWXAjkRd35XPV\n/9RAl06sv191BNFFPyg0\n-----END PRIVATE KEY-----\n'
    #keyB = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBn\n9zn/q8GMs7SJjZ+VLlPG89bB83Cn1kDRmGEdUQF3OSZWIdMAVJb1/xaR4NAhlRya\n7jZHBW5DlUF5rrmecN4A\n-----END PRIVATE KEY-----\n'
    keyA = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBm\nZK4qUqvU6WaPy4fNG9oWIXchxzztxmA7p9BFXbMzn3rHcW84SDwTWXAjkRd35XPV\n/9RAl06sv191BNFFPyg0\n-----END PRIVATE KEY-----\n'
    keyB = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBn\n9zn/q8GMs7SJjZ+VLlPG89bB83Cn1kDRmGEdUQF3OSZWIdMAVJb1/xaR4NAhlRya\n7jZHBW5DlUF5rrmecN4A\n-----END PRIVATE KEY-----\n'
    PlainText = b"Encrypt me with the derived key!"
    
    STD_KEY, STD_CIPHER = DHandEncrypt(keyA, keyB, PlainText)

    print(STD_CIPHER)

    if STD_CIPHER == b'\xd8W\xd1\xfe\xb2\xb9_\x89\x90?O\tF\xde\xeb\xe1\xa1Gx\xb18\x1cY\x1e\xaf\xe0QmL\xf6\xeb\x0e':
        print("Hurray!")

    print(STD_KEY)
