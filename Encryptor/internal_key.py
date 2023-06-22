"""Class and associated functions wrapping and a Fernet Key"""
import pickle
from collections import namedtuple

from cryptography.fernet import Fernet

from fernet_encryption import Encryptor

InternalKey = namedtuple("InternalKey", ("fernetKey", "name", "description"))


def dump_keys(file_path: str, keys: list[InternalKey], encryption_key: Fernet) -> None:
    """Writes the given keys to a file"""
    pickle_data: bytes = pickle.dumps(keys, protocol=pickle.HIGHEST_PROTOCOL)
    enc_pickle: bytes = Encryptor.encrypt_data(pickle_data, encryption_key)
    with open(file_path, 'wb') as file:
        file.write(enc_pickle)


def load_keys(file_path: str, decryption_key: Fernet) -> list[InternalKey]:
    """Loads a key list from file"""
    with open(file_path, 'rb') as file:
        contents = file.read()
    keys: list[InternalKey] = pickle.loads(Encryptor.decrypt_data(contents, decryption_key))
    return keys
