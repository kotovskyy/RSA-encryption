from pngtools.png.PNG import PNG
from rsa.keys import PublicKey, PrivateKey, generate_keypair
from rsa.main import encrypt, decrypt

class PNG_RSA:
    def __init__(self, filename: str):
        self.image = PNG(filename)
        self.key_size = None

    def generate_keypair(self, key_size: int):
        self.public_key, self.private_key = generate_keypair(key_size)
        self.key_size = key_size

    def get_public_key(self) -> PublicKey:
        return self.public_key
    
    def get_private_key(self) -> PrivateKey:
        return self.private_key
    
    def set_public_key(self, key: PublicKey):
        self.public_key = key
        self.key_size = key.n.bit_length()

    def set_private_key(self, key: PrivateKey):
        self.private_key = key
        self.key_size = key.n.bit_length()


    def encrypt(self, method: str):
        self.image.merge_IDAT()
        data = [chunk for chunk in self.image.chunks if chunk.name == "IDAT"][0].data
        encrypted_data = []

        

