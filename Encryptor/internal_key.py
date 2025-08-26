"""Class and associated functions wrapping and a Fernet Key"""
from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.fernet import Fernet

from fernet_encryption import Encryptor


class InternalKey:
    __slots__ = ("fernet_key", "name", "description")

    fernet_key: Fernet
    name: str
    description: str

    def __init__(self, fernet_key: Fernet, name: str, description: str):
        self.name = name
        self.description = description
        self.fernet_key = fernet_key

    def get_url_safe_b64_enc_key(self) -> str:
        fernet_bytes: bytes = self.fernet_key._signing_key + self.fernet_key._encryption_key
        return base64.urlsafe_b64encode(fernet_bytes).decode("ASCII")

    class InternalKeyJSONEncoder(json.JSONEncoder):
        def default(self, o: Any) -> Any:
            if isinstance(o, InternalKey):
                fernet_bytes: bytes = o.fernet_key._signing_key + o.fernet_key._encryption_key
                fernet_str = base64.urlsafe_b64encode(fernet_bytes).decode("ASCII")
                return (fernet_str, o.name, o.description)
            else:
                return json.JSONEncoder.default(self, o)

    @staticmethod
    def _from_json_list(raw_json_list: list[str]) -> InternalKey:
        return InternalKey(Fernet(raw_json_list[0]), raw_json_list[1], raw_json_list[2])

    @staticmethod
    def dump_keys(file_path: str, keys: list[InternalKey], encryption_key: Fernet) -> None:
        """Writes the given keys to a file"""
        json_str: str = json.dumps(keys, cls=InternalKey.InternalKeyJSONEncoder)
        enc_pickle: bytes = Encryptor.encrypt_data(json_str, encryption_key)
        with open(file_path, 'wb') as file:
            file.write(enc_pickle)

    @staticmethod
    def load_keys(file_path: str, decryption_key: Fernet) -> list[InternalKey]:
        """Loads a key list from file"""
        with open(file_path, 'rb') as file:
            contents = file.read()
        keys: list[list[str]] = json.loads(Encryptor.decrypt_data(contents, decryption_key).decode("UTF-8"))
        return [InternalKey._from_json_list(key) for key in keys]

    @staticmethod
    def dump_key(file_path: str, key: InternalKey, encryption_key: Fernet) -> None:
        """Dumps a key to a file"""
        json_bytes: str = json.dumps(key, cls=InternalKey.InternalKeyJSONEncoder)
        encrypted_str = encryption_key.encrypt(json_bytes.encode("UTF-8"))
        with open(file_path, "wb") as file:
            file.write(encrypted_str)

    @staticmethod
    def load_key(file_path: str, encryption_key: Fernet) -> InternalKey:
        """Loads a key from a file"""
        with open(file_path, 'rb') as file:
            encrypted_bytes = file.read()
        json_str = encryption_key.decrypt(encrypted_bytes).decode("UTF-8")
        temp_list = json.loads(json_str)
        return InternalKey._from_json_list(temp_list)
