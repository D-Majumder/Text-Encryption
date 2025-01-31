from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# Padding functions for AES and DES
def pad(text, block_size):
    while len(text) % block_size != 0:
        text += ' '
    return text

# AES encryption and decryption
def aes_encrypt(key, plaintext):
    key = pad(key, 16).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, 16).encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def aes_decrypt(key, ciphertext):
    key = pad(key, 16).encode('utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext)).decode('utf-8').strip()
    return plaintext

# DES encryption and decryption
def des_encrypt(key, plaintext):
    key = pad(key, 8).encode('utf-8')
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext, 8).encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def des_decrypt(key, ciphertext):
    key = pad(key, 8).encode('utf-8')
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext)).decode('utf-8').strip()
    return plaintext

# RSA key generation, encryption, and decryption
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, plaintext):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(private_key, ciphertext):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext)).decode('utf-8')
    return plaintext

# Example usage
private_key, public_key = generate_rsa_keys()
aes_key = 'myAESkey1234567'  # 16-byte key for AES
des_key = 'myDESkey'         # 8-byte key for DES

# Encrypt symmetric keys using RSA
encrypted_aes_key = rsa_encrypt(public_key, aes_key)
encrypted_des_key = rsa_encrypt(public_key, des_key)

# Decrypt symmetric keys using RSA
decrypted_aes_key = rsa_decrypt(private_key, encrypted_aes_key)
decrypted_des_key = rsa_decrypt(private_key, encrypted_des_key)

# Encrypt and decrypt message using AES and DES
plaintext = 'Hello, World!'
aes_ciphertext = aes_encrypt(decrypted_aes_key, plaintext)
des_ciphertext = des_encrypt(decrypted_des_key, plaintext)

print('AES Encrypted:', aes_ciphertext)
print('AES Decrypted:', aes_decrypt(decrypted_aes_key, aes_ciphertext))

print('DES Encrypted:', des_ciphertext)
print('DES Decrypted:', des_decrypt(decrypted_des_key, des_ciphertext))