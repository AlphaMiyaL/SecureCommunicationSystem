import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class Sender:
    def __init__(self, sender_public_key_file, receiver_public_key_file):
        self.private_key = self.__generate_rsa_keys(sender_public_key_file)
        self.public_key = None
        self.receiver_public_key_loc = receiver_public_key_file

    def send_encrypted_message(self, message_file, transmit_file):
        self.__obtain_receiver_public_key()
        aes_key = self.__generate_aes_key()
        message = self.__extract_message(message_file)
        iv, encrypted_message = self.__encrypt_message(aes_key, message)
        encrypted_key = self.__encrypt_key(aes_key)
        mac = self.__compute_mac(aes_key, iv, encrypted_message)
        signature = self.__sign_mac(mac)
        self.transmit_data(transmit_file, encrypted_key, iv, mac, signature, encrypted_message)
        # print("iv: ", iv)
        # print("Sender; message:", message)
        # print("Sender; en_message:", encrypted_message)
        # print("Sender; mac:", mac)
        # print("Sender; signature:", signature)

    def __generate_rsa_keys(self, sender_public_key_file):
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
        with open(sender_public_key_file, 'wb') as file:
            file.write(sender_public_key_pem)
        return sender_private_key_pem

    def __obtain_receiver_public_key(self):
        with open(self.receiver_public_key_loc, 'rb') as file:
            self.public_key = file.read()

    def __generate_aes_key(self):
        aes_key = os.urandom(32)
        return aes_key

    def __extract_message(self, message_file):
        with open(message_file, 'rb') as file:
            message = file.read()
            return message

    def __encrypt_message(self, aes_key, message):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_message = padder.update(message) + padder.finalize()
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        return iv, encrypted_message

    def __encrypt_key(self, aes_key):
        public_key = load_pem_public_key(self.public_key, backend=default_backend())
        encrypted_aes_key = public_key.encrypt(aes_key, asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        return encrypted_aes_key

    def __compute_mac(self, aes_key, iv, encrypted_message):
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(aes_key)
        h.update(iv)
        h.update(encrypted_message)
        mac = h.finalize()
        return mac

    def __sign_mac(self, mac):
        private_key = load_pem_private_key(self.private_key, password=None, backend=default_backend())
        signature = private_key.sign(
            mac,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return signature

    # does not actually transmit data, simply places in a file given
    def transmit_data(self, filepath, encrypted_key, iv, mac, signature, encrypted_message):
        # print("Encrypted Message Size:", len(encrypted_message))
        # print("Encrypted Key Size:", len(encrypted_key))
        # print("MAC Size:", len(mac))
        # print("iv Size:", len(iv))
        # print("Signature Size:", len(signature))
        with open(filepath, 'wb') as file:
            file.write(encrypted_key)
            file.write(iv)
            file.write(mac)
            file.write(signature)
            file.write(encrypted_message)
