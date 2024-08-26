import base64
import os

# Generate a 256-bit AES key
key = os.urandom(32)
# Encode the key in Base64
base64_key = base64.b64encode(key).decode('utf-8')
print(f"Base64 Encoded Key: {base64_key}")
