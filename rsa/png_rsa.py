import zlib
from pngtools.png.PNG import PNG
from pngtools.png.chunks import Chunk
from rsa.keys import PublicKey, PrivateKey, generate_keypair
from rsa.main import encrypt, decrypt
from rsa.cipher_mode import ECB


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
        chunk = [chunk for chunk in self.image.chunks if chunk.name == "IDAT"][0]
        encrypted_data = []
        if method == "ECB":
            mode = ECB(self.public_key, self.private_key)
        encrypted_data = mode.encrypt(chunk.data)
        new_chunk = Chunk(
            "IDAT",
            len(encrypted_data),
            encrypted_data,
            PNG._calculateCRC("IDAT", encrypted_data),
        )

        print(f"Chunk data before: {len(chunk.data)}")
        print(f"Chunk data after: {len(new_chunk.data)}")

        index = self.image.chunks.index(chunk)
        self.image.chunks.remove(chunk)
        self.image.chunks.insert(index, new_chunk)

        self.image.printData()
        self.image.saveFile("encrypted.png", True)

        return encrypted_data

    def decrypt(self, method: str):
        self.image.merge_IDAT()
        chunk = [chunk for chunk in self.image.chunks if chunk.name == "IDAT"][0]
        decrypted_data = []
        if method == "ECB":
            mode = ECB(self.public_key, self.private_key)

        decrypted_data = mode.decrypt(chunk.data)
        new_chunk = Chunk(
            "IDAT",
            len(decrypted_data),
            decrypted_data,
            PNG._calculateCRC("IDAT", decrypted_data),
        )

        print(f"Chunk data before: {len(chunk.data)}")
        print(f"Chunk data after: {len(new_chunk.data)}")

        index = self.image.chunks.index(chunk)
        self.image.chunks.remove(chunk)
        self.image.chunks.insert(index, new_chunk)

        self.image.printData()
        self.image.saveFile("decrypted.png", True)

        return decrypted_data


def main():
    filepath = "pngtools/images/image2.png"
    encryptor = PNG_RSA(filepath)
    encryptor.generate_keypair(2048)
    encrypted_data = encryptor.encrypt("ECB")
    decrypted_data = encryptor.decrypt("ECB")

    # import matplotlib.pyplot as plt
    # plt.imshow(plt.imread("encrypted.png"))
    # plt.show()


if __name__ == "__main__":
    main()
