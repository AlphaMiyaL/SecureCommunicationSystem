import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import utils

class Sender:
    def __init__(self, reciever_public_rsa_key, sender_private_rsa_key):
        self.public_key = reciever_public_rsa_key
        self.private_key = sender_private_rsa_key

    def send_encrypted_message(self, message_file, transmit_file):
        aes_key = self.__generate_aes_key()
        message = self.__extract_message(message_file)
        encrypted_message = self.__encrypt_message(aes_key, message)
        encrypted_key = self.__encrypt_key(aes_key)
        mac = self.__compute_mac(aes_key, encrypted_message)
        signature = self.__sign_mac(mac)
        self.transmit_data(transmit_file, encrypted_message, encrypted_key, signature)

    def __generate_aes_key(self):
        aes_key = os.urandom(32)
        return aes_key

    def __extract_message(self, message_file):
        with open(message_file, 'rb') as f:
            message = f.read()
            return message

    def __encrypt_message(self, aes_key, message):
        self.iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        padded_message = padder.update(message) + padder.finalize()
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        return encrypted_message

    def __encrypt_key(self, aes_key):
        public_key = load_pem_public_key(self.public_key, backend=default_backend())
        encrypted_aes_key = public_key.encrypt(aes_key, asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        return encrypted_aes_key

    def __compute_mac(self, aes_key, encrypted_message):
        h = hashes.Hash(hashes.SHA256(), backend=default_backend())
        h.update(aes_key)
        h.update(self.iv)
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
    def transmit_data(self, filepath, encrypted_message, encrypted_key, signature):
        with open(filepath, 'wb') as file:
            file.write(encrypted_message)
            file.write(encrypted_key)
            file.write(signature)
