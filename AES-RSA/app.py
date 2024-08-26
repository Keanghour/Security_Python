import base64
from flask import Flask, request, jsonify
from crypto import generate_aes_key, encrypt_aes, decrypt_aes, encrypt_rsa, decrypt_rsa
from key_manager import load_rsa_keys

app = Flask(__name__)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        public_key, _ = load_rsa_keys()
        data = request.json.get('data')

        if not data:
            return jsonify({'error': 'Missing data parameter'}), 400

        aes_key = generate_aes_key()
        encrypted_data = encrypt_aes(data, aes_key)
        base64_aes_key = base64.b64encode(aes_key).decode('utf-8')
        encrypted_aes_key = encrypt_rsa(base64_aes_key, public_key)
        
        return jsonify({
            'encrypted_data': encrypted_data,
            'encrypted_aes_key': encrypted_aes_key
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        _, private_key = load_rsa_keys()
        encrypted_data = request.json.get('encrypted_data')
        encrypted_aes_key = request.json.get('encrypted_aes_key')

        if not encrypted_data or not encrypted_aes_key:
            return jsonify({'error': 'Missing encrypted_data or encrypted_aes_key parameters'}), 400

        base64_aes_key = decrypt_rsa(encrypted_aes_key, private_key)
        aes_key = base64.b64decode(base64_aes_key)
        decrypted_data = decrypt_aes(encrypted_data, aes_key)
        
        return jsonify({'decrypted_data': decrypted_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=3000)
