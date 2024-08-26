import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

def sign_data(data, private_key_pem):
    try:
        private_key = load_pem_private_key(private_key_pem, password=None)
        signature = private_key.sign(
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

def verify_signature(data, signature, public_key_pem):
    try:
        signature_bytes = base64.b64decode(signature)
        public_key = load_pem_public_key(public_key_pem)
        public_key.verify(
            signature_bytes,
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

def encrypt_data(data, public_key_pem):
    try:
        public_key = load_pem_public_key(public_key_pem)
        encrypted_bytes = public_key.encrypt(
            data.encode('utf-8'),
            padding.PKCS1v15()
        )
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_data(encrypted_data, private_key_pem):
    try:
        private_key = load_pem_private_key(private_key_pem, password=None)
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.PKCS1v15()
        )
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem
