from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

app = Flask(__name__)

def verify_signature(data, base64_signature, base64_public_key):
    # Decode the Base64-encoded signature
    signature_bytes = base64.b64decode(base64_signature)
    
    # Decode the Base64-encoded public key
    public_key_bytes = base64.b64decode(base64_public_key)
    
    # Load the public key
    try:
        public_key = serialization.load_der_public_key(public_key_bytes)
    except ValueError as e:
        print(f"Failed to load public key: {e}")
        return False

    # Verify the signature
    try:
        public_key.verify(
            signature_bytes,
            data.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Verification failed: {e}")
        return False

@app.route('/verify', methods=['POST'])
def verify():
    try:
        # Extract JSON data from the request
        data = request.json.get('data')
        base64_signature = request.json.get('signature')
        base64_public_key = request.json.get('public_key')

        # Verify the signature
        is_verified = verify_signature(data, base64_signature, base64_public_key)
        return jsonify({'verified': is_verified})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, port=8889)
