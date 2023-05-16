from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sender import Sender

if __name__ == '__main__':
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Serialize the public key
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    message_filepath = "Files/plaintext_message.txt"
    transmit_data_filepath = "Files/transmitted_data.txt"
    sender = Sender(public_key_pem)
    sender.send_encrypted_message(message_filepath, transmit_data_filepath)
