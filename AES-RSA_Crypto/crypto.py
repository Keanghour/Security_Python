import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
import base64

def generate_aes_key():
    """Generate a 256-bit AES key."""
    return os.urandom(32)  # 256-bit key

def encrypt_aes(data, key):
    """Encrypt data using AES in ECB mode."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    
    # Ensure data is in bytes
    data_bytes = data.encode('utf-8')
    
    # Pad data to be a multiple of block size (16 bytes for AES)
    padder = pad.PKCS7(algorithms.AES.block_size).padder()
    data_padded = padder.update(data_bytes) + padder.finalize()
    
    encrypted = encryptor.update(data_padded) + encryptor.finalize()
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_aes(base64_data, key):
    """Decrypt data using AES in ECB mode."""
    encrypted_data = base64.b64decode(base64_data)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = pad.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return decrypted.decode('utf-8')

def encrypt_rsa(data, public_key):
    """Encrypt data using RSA."""
    encrypted = public_key.encrypt(
        data.encode('utf-8'),
        asymmetric_padding.PKCS1v15()
    )
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_rsa(base64_data, private_key):
    """Decrypt data using RSA."""
    encrypted_data = base64.b64decode(base64_data)
    decrypted = private_key.decrypt(
        encrypted_data,
        asymmetric_padding.PKCS1v15()
    )
    return decrypted.decode('utf-8')
