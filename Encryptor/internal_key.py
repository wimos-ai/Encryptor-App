import pickle
from collections import namedtuple

from cryptography.fernet import Fernet

from fernet_encryption import Encryptor


InternalKey = namedtuple("InternalKey", ("fernetKey", "name", "description"))


def dump_keys(file_path: str, keys: list[InternalKey], encryption_key: Fernet):
    enc_pickle = Encryptor.encrypt_data(pickle.dumps(keys, protocol=pickle.HIGHEST_PROTOCOL), encryption_key)
    with open(file_path, 'wb') as file:
        file.write(enc_pickle)


def load_keys(file_path: str, decryption_key: Fernet) -> list[InternalKey]:
    with open(file_path, 'rb') as file:
        contents = file.read()
    return pickle.loads(Encryptor.decrypt_data(contents, decryption_key))
