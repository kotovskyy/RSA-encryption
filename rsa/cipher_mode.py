from rsa.keys import PublicKey
from rsa.main import encrypt, decrypt


class AbstractMode:
    def __init__(self, key: PublicKey, data: bytes):
        self.key = key
        self.data = data

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, data: bytes) -> bytes:
        raise NotImplementedError


class ECB(AbstractMode):
    def encrypt(self, data: bytes) -> bytes:
        pass

    def decrypt(self, data: bytes) -> bytes:
        pass
