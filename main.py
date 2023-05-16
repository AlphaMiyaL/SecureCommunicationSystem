from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sender import Sender

if __name__ == '__main__':
    # Generate RSA key pair for sender
    sender_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Serialize the sender's public key
    sender_public_key = sender_private_key.public_key()
    sender_public_key_pem = sender_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Serialize the sender's private key
    sender_private_key_pem = sender_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Generate RSA key pair for receiver
    receiver_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Serialize the receiver's public key
    receiver_public_key = receiver_private_key.public_key()
    receiver_public_key_pem = receiver_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    message_filepath = "Files/plaintext_message.txt"
    transmit_data_filepath = "Files/transmitted_data.txt"
    sender = Sender(receiver_public_key_pem, sender_private_key_pem)
    sender.send_encrypted_message(message_filepath, transmit_data_filepath)