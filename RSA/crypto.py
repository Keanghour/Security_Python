from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import base64

class RSAEncryption:
    @staticmethod
    def encrypt(data, public_key):
        """
        Encrypts data using the provided public key with PKCS1v15 padding.

        :param data: Data to encrypt (string).
        :param public_key: The public RSA key.
        :return: The encrypted data (base64 encoded).
        """
        encrypted_bytes = public_key.encrypt(
            data.encode('utf-8'),
            padding.PKCS1v15()  # PKCS1v15 padding
        )
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    @staticmethod
    def decrypt(base64_data, private_key):
        """
        Decrypts data using the provided private key with PKCS1v15 padding.

        :param base64_data: Encrypted data (base64 encoded string).
        :param private_key: The private RSA key.
        :return: The decrypted data (string).
        """
        encrypted_bytes = base64.b64decode(base64_data)
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.PKCS1v15()  # PKCS1v15 padding
        )
        return decrypted_bytes.decode('utf-8')
