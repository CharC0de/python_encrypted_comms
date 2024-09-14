from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP


def generate_rsa_key_pair():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()


def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return cipher.nonce + tag + ciphertext


def decrypt_message(encrypted_message, aes_key):
    nonce, tag, ciphertext = encrypted_message[:
                                               16], encrypted_message[16:32], encrypted_message[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode('utf-8')


def encrypt_aes_key(aes_key, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key


def decrypt_aes_key(encrypted_key, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(encrypted_key)
    return aes_key
