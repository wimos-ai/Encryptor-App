"""Module for encryption functions based on cryptography"""
import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encryptor:
    """Exposes some convenient methods working with Fernet objects"""

    @staticmethod
    def create_key(password: str) -> Fernet:
        """Creates a Fernet key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"}'x\x08\xab\t\xf5Ik,\xc3\xf4i\xf4\xc4\xe3",
            iterations=600001,
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode("UTF-8")))
        return Fernet(key)

    @staticmethod
    def create_random_key() -> Fernet:
        """Creates a random Fernet key"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"}'x\x08\xab\t\xf5Ik,\xc3\xf4i\xf4\xc4\xe3",
            iterations=600001,
        )
        bts = os.urandom(32)
        key = base64.urlsafe_b64encode(kdf.derive(bts))
        return Fernet(key)

    @staticmethod
    def write_key(file_name: str, key: bytes, enc_key: Fernet) -> None:
        """Writes a Fernet key to file encrypts it"""
        with open(file_name, "wb") as file:
            file.write(enc_key.encrypt(key))

    @staticmethod
    def read_key(file_path: str, enc_key: Fernet) -> bytes:
        """Reads an encrypted key from file"""
        with open(file_path, 'rb') as file:
            return enc_key.decrypt(file.read())

    @staticmethod
    def encrypt_data(data: str | bytes, key: Fernet) -> bytes:
        """Encrypts given data"""
        if isinstance(data, str):
            return key.encrypt(data.encode("UTF-8"))
        return key.encrypt(data)

    @staticmethod
    def decrypt_data(data: bytes, key: Fernet) -> bytes:
        """Decrypts data to bytes"""
        return key.decrypt(data)

    @staticmethod
    def encrypt_file(file_path: str, key: Fernet) -> None:
        """Encrypts a file"""
        with open(file_path, 'rb') as file:
            contents = file.read()

        with open(file_path, 'wb') as file:
            file.write(key.encrypt(contents))

    @staticmethod
    def decrypt_file(file_path: str, key: Fernet) -> None:
        """Decrypts a file"""
        with open(file_path, 'rb') as file:
            contents = file.read()
        with open(file_path, 'wb') as file:
            file.write(key.decrypt(contents))
