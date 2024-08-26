import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding

def generate_aes_key():
    return os.urandom(32)  # 256-bit AES key

def encrypt_aes(data, key):
    """Encrypt data using AES in CBC mode."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Ensure data is in bytes
    data_bytes = data.encode('utf-8')
    
    # Pad data to be a multiple of block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    data_padded = padder.update(data_bytes) + padder.finalize()
    
    encrypted = encryptor.update(data_padded) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode('utf-8')  # Prepend IV to encrypted data

def decrypt_aes(base64_data, key):
    """Decrypt data using AES in CBC mode."""
    data = base64.b64decode(base64_data)
    iv = data[:16]  # Extract IV
    encrypted_data = data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return decrypted.decode('utf-8')

def encrypt_rsa(data, public_key):
    """Encrypt data using RSA."""
    encrypted = public_key.encrypt(
        data.encode('utf-8'),
        asymmetric_padding.PKCS1v15()  # Use PKCS1v15 padding
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_rsa(base64_data, private_key):
    """Decrypt data using RSA."""
    encrypted_data = base64.b64decode(base64_data)
    decrypted = private_key.decrypt(
        encrypted_data,
        asymmetric_padding.PKCS1v15()  # Use PKCS1v15 padding
    )
    return decrypted.decode('utf-8')
