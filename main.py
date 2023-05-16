from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from receiver import Receiver
from sender import Sender

if __name__ == '__main__':
    sender_public_key_filepath = "Files/sender_public_key.txt"
    receiver_public_key_filepath = "Files/receiver_public_key.txt"
    message_filepath = "Files/plaintext_message.txt"
    transmit_data_filepath = "Files/transmitted_data.txt"
    sender = Sender(sender_public_key_filepath, receiver_public_key_filepath)
    receiver = Receiver(receiver_public_key_filepath, sender_public_key_filepath)
    sender.send_encrypted_message(message_filepath, transmit_data_filepath)
    receiver.receive_encrypted_message(transmit_data_filepath)
