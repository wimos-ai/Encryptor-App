# cython: language_level=3
# cython: embedsignature = True

import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class Encryptor:
    # cdef __defKey__ = b'LRpy6OLfl9lWweZX8Qm84_hrhX5_V5-OyqBm9Zf216M='
    # Returns Bytes Object
    @staticmethod
    def create_key(password: str = None):
        if password is None:
            return Fernet.generate_key()
        else:
            password = bytes(password, encoding="Utf-8")
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"}'x\x08\xab\t\xf5Ik,\xc3\xf4i\xf4\xc4\xe3",
                iterations=390000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password))
            return Fernet(key)

    @staticmethod
    def write_key(file, key, encKey=None):
        if encKey is None:
            defKeyArray = [b'LR', b'py', b'6O', b'Lf', b'l9', b'lW', b'we', b'ZX', b'8Q', b'm8', b'4_', b'hr', b'hX',
                           b'5_', b'V5', b'-O', b'yq', b'Bm', b'9Z', b'f2', b'16', b'M', b'=']
            defKey = b''
            for part in defKeyArray:
                defKey = defKey + part
            k = Fernet(b'LRpy6OLfl9lWweZX8Qm84_hrhX5_V5-OyqBm9Zf216M=')
        else:
            k = Fernet(encKey)
        f = open(file, 'wb')
        f.write(k.encrypt(key))
        f.close()

    @staticmethod
    def read_key(file, encKey=None):
        if encKey is None:
            defKeyArray = [b'LR', b'py', b'6O', b'Lf', b'l9', b'lW', b'we', b'ZX', b'8Q', b'm8', b'4_', b'hr', b'hX',
                           b'5_', b'V5', b'-O', b'yq', b'Bm', b'9Z', b'f2', b'16', b'M', b'=']
            defKey = b''
            for part in defKeyArray:
                defKey = defKey + part
            k = Fernet(b'LRpy6OLfl9lWweZX8Qm84_hrhX5_V5-OyqBm9Zf216M=')
        else:
            k = Fernet(encKey)
        with open(file, 'rb') as f:
            return k.decrypt(f.read())

    # DATA IS CHANGED TO BYTES
    @staticmethod
    def encrypt_data(data, key):
        if not isinstance(key, Fernet):
            key = Fernet(key)
        # Strings are assumed to be UTF-8
        if isinstance(data, str):
            return key.encrypt(bytes(data, encoding='utf8'))
        return key.encrypt(bytes(data))

    @staticmethod
    def decrypt_data(data, key, mode='b'):
        if not isinstance(key, Fernet):
            key = Fernet(key)
        if mode == 'b':
            return key.decrypt(data)
        if mode == 's':
            return str(key.decrypt(data))[2:-1]
        if mode == 'i':
            return int(key.decrypt(data))

    @staticmethod
    def encrypt_file(file, key):
        with open(file, 'rb') as f:
            contents = f.read()

        if isinstance(key, bytes):
            with open(file, 'wb') as f:
                k = Fernet(key)
                f.write(k.encrypt(contents))
        else:
            with open(file, 'wb') as f:
                k = key
                f.write(k.encrypt(contents))

    @staticmethod
    def decrypt_file(file, key):
        with open(file, 'rb') as f:
            contents = f.read()
        if isinstance(key, bytes):
            k = Fernet(key)
        else:
            k = key
        dec = k.decrypt(contents) # Needs tmp variable otherwise function call returns none and that is what is written
        with open(file, 'wb') as f:
            f.write(dec)
