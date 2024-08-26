from flask import Flask, request, jsonify
from crypto import RSAEncryption
from key_manager import load_key
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load RSA keys
public_key = load_key('KEY/public_key.pem', is_public_key=True)
private_key = load_key('KEY/private_key.pem', is_public_key=False)

if public_key is None or private_key is None:
    logging.error("Failed to load RSA keys.")
    raise ValueError("Failed to load RSA keys.")

@app.route('/encrypt', methods=['POST'])
def encrypt_data():
    try:
        data = request.json.get('data')
        if not data:
            return jsonify({"error": "No data provided"}), 400
        encrypted_data = RSAEncryption.encrypt(data, public_key)
        return jsonify({"encrypted_data": encrypted_data})
    except Exception as e:
        logging.error(f"Encryption error: {e}")
        return jsonify({"error": "Encryption failed"}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_data():
    try:
        encrypted_data = request.json.get('encrypted_data')
        if not encrypted_data:
            return jsonify({"error": "No encrypted data provided"}), 400
        decrypted_data = RSAEncryption.decrypt(encrypted_data, private_key)
        return jsonify({"decrypted_data": decrypted_data})
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return jsonify({"error": "Decryption failed"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=8888)
