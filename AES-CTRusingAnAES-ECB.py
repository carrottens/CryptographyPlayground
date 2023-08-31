# ***********
# Task 3
# ***********
# An implementation of AES in CTR mode using the cryptography.io modules is provided.
# Re-implement the function using ONLY the ECB mode of AES, 
# i.e., implement the encrypt operation of AES-CTR using an AES-ECB cipher and encryptor

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def RepeatingXOREncrypt(key, string):
    # Convert the key into bytes
    keyBytes = bytes(key)

    # XOR the key in byte format with string in byte format
    result = bytes([string[i]^keyBytes[i%len(keyBytes)] for i in range(len(string))])

    # Return the XOR value in bytes
    return result

# AES in ECB mode encryption
def AES_CTR_Encrypt(key, nonce_counter, data):

    # Convert the key into bytes
    key = bytes.fromhex(key)

    # Convert nonce_counter into a byte array for modification possibilities
    nonceCounterTracker = int(nonce_counter)
    nonce_counter = bytearray(bytes.fromhex(nonce_counter))

    # Do not allow passing a counter that does not satisfy the AES block size (16 bytes)
    if len(nonce_counter)%16 != 0:
        return 0
    
    # Create an AES encryptor in ECB mode
    aesCipher = Cipher(algorithms.AES(key), modes.ECB())
    aesEncryptor = aesCipher.encryptor()

    # Intiailise the variable where the final result will be stored
    cipherText = b''

    # Encrypt the data
    for i in range(int((len(data)/16))):
        encryptedCounter = aesEncryptor.update(nonce_counter)
        nonceCounterTracker += 1
        nonce_counter[len(nonce_counter)-1] = nonceCounterTracker
        cipherText += RepeatingXOREncrypt(encryptedCounter, data[i*16:i*16+16])
    
    # Dealing with the possible residual data
    if len(data)%16 != 0:
        encryptedCounter = aesEncryptor.update(nonce_counter)
        cipherText += RepeatingXOREncrypt(encryptedCounter, data[len(data)-len(data)%16:len(data)])
    return cipherText

# Testing
# Main
if __name__ == "__main__":
    key = '0000000000000000000000000000000000000000000000000000000000000002'
    nonce_counter = '00000000000000000000000000000002'
    data = b"123456789012345678901234567890121234567890123456789012345678901212345678901234567890123456789012"
    result = AES_CTR_Encrypt(key, nonce_counter, data)
    print(result)