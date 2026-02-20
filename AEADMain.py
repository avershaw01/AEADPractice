#!/usr/bin/env python3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt(key, plaintext, aad):
    """
    Encrypts plaintext using AES-GCM.

    A fresh, random 96-bit nonce (number used once) is generated for each encryption.
    The returned message is nonce || ciphertext.

    WARNING: Reusing a nonce with the same key breaks security.
    """
    nonce = os.urandom(12)  # GCM standard nonce/IV size

    # Instantiates AES-GCM with the given key
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    return nonce + ciphertext

def decrypt(key, message, aad):
    """
    Decrypts a message produced by encrypt()

    Expects input formatted as nonce || ciphertext.
    """
    nonce = message[:12]
    ciphertext = message[12:]
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, aad)


if __name__ == "__main__":
    # os uses the operating system's random # generator
    # to create cryptographically secure random bytes
    key = os.urandom(32)  # 256-bit AES key

    plaintext = b"this is a plaintext message"
    associated_data = b"this is associated data"

    encrypted_message = encrypt(key, plaintext, associated_data)
    print("Encryption successful!")

    # Now decrypt using same engine
    try:
        decrypted_text = decrypt(key, encrypted_message, associated_data)
        print("Decryption successful!")
        print("decrypted text:", decrypted_text.decode('utf-8'))
    except Exception as e:
        print("Decryption failed:", e)
