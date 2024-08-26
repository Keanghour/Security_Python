from cryptography.hazmat.primitives import serialization
import logging

def load_key(path, is_public_key=True):
    """
    Load an RSA key from a PEM file.

    :param path: Path to the PEM file.
    :param is_public_key: Boolean flag to indicate if the key is a public key.
    :return: The loaded public or private RSA key, or None if loading failed.
    """
    try:
        with open(path, 'rb') as key_file:
            if is_public_key:
                # Load the public key
                return serialization.load_pem_public_key(key_file.read())
            else:
                # Load the private key
                return serialization.load_pem_private_key(key_file.read(), password=None)
    except FileNotFoundError:
        logging.error(f"Error: The file at path '{path}' was not found.")
    except ValueError as e:
        logging.error(f"Error loading key: {e}")
    except Exception as e:
        logging.error(f"Unexpected error loading key: {e}")
    return None
