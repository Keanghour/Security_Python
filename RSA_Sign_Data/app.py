from flask import Flask, request, jsonify
from key_manager import generate_keys
from crypto import sign_data, verify_signature
import base64

app = Flask(__name__)

@app.route('/generate-keys', methods=['POST'])
def generate_keys_endpoint():
    try:
        private_key_pem, public_key_pem = generate_keys()
        return jsonify({
            'private_key': base64.b64encode(private_key_pem).decode('utf-8'),
            'public_key': base64.b64encode(public_key_pem).decode('utf-8')
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sign', methods=['POST'])
def sign_data_endpoint():
    try:
        data = request.json.get('data')
        private_key_b64 = request.json.get('private_key')
        if not data or not private_key_b64:
            return jsonify({'error': 'Missing data or private_key'}), 400
        
        private_key_pem = base64.b64decode(private_key_b64)
        signature = sign_data(data, private_key_pem)
        return jsonify({'signature': signature}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify', methods=['POST'])
def verify_signature_endpoint():
    try:
        data = request.json.get('data')
        signature = request.json.get('signature')
        public_key_b64 = request.json.get('public_key')
        if not data or not signature or not public_key_b64:
            return jsonify({'error': 'Missing data, signature, or public_key'}), 400
        
        public_key_pem = base64.b64decode(public_key_b64)
        is_verified = verify_signature(data, signature, public_key_pem)
        return jsonify({'verified': is_verified}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=7070)
