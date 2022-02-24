import pickle

from fernetEncryption import Encryptor


class InternalKey:
    def __init__(self, fernetKey, name, description):
        self.fernetKey = fernetKey
        self.name = name
        self.description = description

    def __str__(self):
        return str(self.__dict__)


def dumpKeys(file, keys, encryptionKey):
    enc_pickle = Encryptor.encrypt_data(pickle.dumps(keys, protocol=pickle.HIGHEST_PROTOCOL), encryptionKey)
    with open(file, 'wb') as File:
        File.write(enc_pickle)


def loadKeys(file, decryptionKey):
    with open(file, 'rb') as File:
        contents = File.read()
    return pickle.loads(Encryptor.decrypt_data(contents, decryptionKey))
