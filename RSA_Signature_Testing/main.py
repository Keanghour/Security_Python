from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

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

# Example usage
if __name__ == "__main__":
    # These values should be provided
    data = "This is a test."
    base64_signature = "VeDEH5xZXqwM/Lq9oCsi3h0gN55LZegLtBJ7NHM1fyWaVdKCc7aSWNH2svLEDPaTHUH2idbdINFufTB/5aaOi/0zVlc1o9QW5J6vV6uZ6jTE3i8vKTeAAlJG7kQ24LAyC2gu7rr2mpje4CO1C1HB/XFe+riUF42/H0vSfjOG/NYgeCtgTiye+jE3RBbaFYZRcrAfgVw1zhRsh5bCL+bxfY/xG9H7Jv3Gsr1dvo0jZfUWUL7HJZp976RtpI5vuNP9yAQv6Qtcxf3vJ8VmdzpfAuuuAxmJt2IwO18qwqRWWgi9ZAL3Vyd1eN3MbNZQ31dNcjQUKX8e0D+MrtrFsRcHbQ=="  # Replace with your Base64 encoded signature
    base64_public_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApV5Lu3Uaxigke6xo+M0NkgWp9lbnG377KRHtMMwuIQaXtS9XapHp8x6t7FVzLoL71BOEs5LPJbekXuagfJK9aA1mHTSkHqtwfMbhI6L/5PGTf8DO71fv1r9ITcGVA27J405gEPagDVlsXkre8lnGXamuf7YprQeFa0hbr9TRstaHFgQIBcPxOX8eoFP00XfcIARKQUkQOdZq59/s5JukOXnnDUtFUOpne9VrBj/bJfZ6vRnexvgpF4xsx1v58DL1mSoQfgz66w6bc1TgiMn8vzFrsuy9DJBc5HNt2mlELm+RwHyjiHlZR0TxBXFYNVdvAgIvRCSF5aapNVuUdFNHLQIDAQAB"  # Replace with your Base64 encoded public key

    is_verified = verify_signature(data, base64_signature, base64_public_key)
    print(f"Signature Verified: {is_verified}")
