import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

def sign_data(data, private_key_pem):
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        signature = private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    except Exception as e:
        raise ValueError(f"Signing failed: {str(e)}")

def verify_signature(data, signature, public_key_pem):
    try:
        signature_bytes = base64.b64decode(signature)
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(
            signature_bytes,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False
