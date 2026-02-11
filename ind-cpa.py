from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import hashlib

# Function to encrypt a message using AES CBC mode
def aes_cbc_encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext

# Function to decrypt a message using AES CBC mode
def aes_cbc_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# Function to generate a symmetric AES key and an initialization vector (IV)
def generate_aes_key_iv():
    key = get_random_bytes(16)  # AES-128 key (16 bytes)
    iv = get_random_bytes(AES.block_size)  # Initialization Vector
    return key, iv

# Simulation of a Chosen Plaintext Attack (CPA)
def chosen_plaintext_attack(plaintext1, plaintext2):
    # Generate AES encryption key and IV
    key, iv = generate_aes_key_iv()

    # Encrypt both plaintext messages
    ciphertext1 = aes_cbc_encrypt(key, iv, plaintext1)
    ciphertext2 = aes_cbc_encrypt(key, iv, plaintext2)

    # An attacker attempts to distinguish between the two ciphertexts
    # In a secure IND-CPA scenario, the attacker should not be able to determine
    # which plaintext corresponds to which ciphertext.
    return ciphertext1, ciphertext2

# Running the attack with two plaintext messages
plaintext1 = "This is a confidential message!"
plaintext2 = "This is another confidential message!"
ciphertext1, ciphertext2 = chosen_plaintext_attack(plaintext1, plaintext2)

print("Ciphertext 1:", ciphertext1.hex())
print("Ciphertext 2:", ciphertext2.hex())

# In a real-world scenario, the attacker should not be able to distinguish
# between the two ciphertexts without knowing the encryption key.
