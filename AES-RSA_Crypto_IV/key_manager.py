from cryptography.hazmat.primitives import serialization

def load_rsa_keys():
    """Load RSA public and private keys from PEM files."""
    try:
        with open('KEY/public_key.pem', 'rb') as pub_file:
            public_key = serialization.load_pem_public_key(pub_file.read())
        
        with open('KEY/private_key.pem', 'rb') as priv_file:
            private_key = serialization.load_pem_private_key(priv_file.read(), password=None)
        
        return public_key, private_key
    except Exception as e:
        raise RuntimeError(f"Error loading RSA keys: {e}")
