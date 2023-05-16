import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class Receiver:
    def __init__(self, receiver_public_key_file, sender_public_key_file):
        self.private_key = self.__generate_rsa_keys(receiver_public_key_file)
        self.public_key = None
        self.sender_public_key_loc = sender_public_key_file

    def receive_encrypted_message(self, transmit_file):
        self.__obtain_sender_public_key()
        encrypted_message, encrypted_key, mac, signature, iv = self.__load_transmitted_data(transmit_file)
        # print("Receiver; en_message:", encrypted_message)
        # print("Receiver; mac:", mac)
        # print("Receiver; signature:", signature)
        if self.__verify_signature(signature, mac):
            decoded_key = self.__decrypt_key(encrypted_key)
            decrypted_message = self.__decrypt_message(decoded_key, iv, encrypted_message)
            print("Signature is valid.")
            print("Decoded Message:", decrypted_message)
        else:
            print("Invalid signature.")

    def __generate_rsa_keys(self, receiver_public_key_file):
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
        # Serialize the receiver's private key
        receiver_private_key_pem = receiver_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(receiver_public_key_file, 'wb') as file:
            file.write(receiver_public_key_pem)
        return receiver_private_key_pem

    def __obtain_sender_public_key(self):
        with open(self.sender_public_key_loc, 'rb') as file:
            self.public_key = file.read()

    def __load_transmitted_data(self, transmit_file):
        with open(transmit_file, 'rb') as file:
            encrypted_key = file.read(256)  # Assuming RSA key size is 2048 bits
            iv = file.read(16)
            mac = file.read(32)  # Assuming iv is 16
            signature = file.read(256)
            encrypted_message = file.read()

        return encrypted_message, encrypted_key, mac, signature, iv

    def __decrypt_key(self, encrypted_key):
        private_key = load_pem_private_key(
            self.private_key,
            password=None,
            backend=default_backend()
        )
        aes_key = private_key.decrypt(
            encrypted_key,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key

    def __decrypt_message(self, aes_key, iv, encrypted_message):
        # iv = os.urandom(16)
        # print(iv)
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()
        return unpadded_message

    def __verify_signature(self, signature, mac):
        public_key = load_pem_public_key(self.public_key, backend=default_backend())
        try:
            public_key.verify(
                signature,
                mac,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            import traceback
            traceback.print_exc()
            return False

