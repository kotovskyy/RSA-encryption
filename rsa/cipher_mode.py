import random
from rsa.keys import PublicKey, PrivateKey, generate_keypair
from rsa.main import encrypt, decrypt


class AbstractMode:
    def __init__(self, publick_key: PublicKey, private_key: PrivateKey):
        self.public_key = publick_key
        self.private_key = private_key
        self.key_size = publick_key.n.bit_length() // 8
        self.block_size = self.key_size - 11  # min 11 bytes for padding

    def encrypt(self, data: bytes) -> bytes:
        raise NotImplementedError

    def decrypt(self, data: bytes) -> bytes:
        raise NotImplementedError


class ECB(AbstractMode):
    def add_padding(self, data_block: bytes) -> bytes:
        if len(data_block) > self.block_size:
            raise ValueError("Data is too long")

        padding_size = self.key_size - len(data_block) - 3
        padding = b"\x00" + b"\x02" + random.randbytes(padding_size).replace(b"\x00", b"\x01") + b"\x00"

        return padding + data_block

    def encrypt_block(self, data_block: bytes) -> bytes:
        padded_data = self.add_padding(data_block)
        return encrypt(self.public_key, int.from_bytes(padded_data, byteorder="big"))

    def encrypt(self, data: bytes) -> bytes:
        encrypted_data = b""
        for i in range(0, len(data), self.block_size):
            data_block = data[i : i + self.block_size]
            encrypted_data += self.encrypt_block(data_block)
        return encrypted_data

    def remove_padding(self, data_block: bytes):
        padding = data_block[0:2]
        if padding != b"\x00\x02":
            raise ValueError("Invalid padding")
        padding_end = data_block.find(b"\x00", 2)
        
        return data_block[padding_end+1:]

    def decrypt_block(self, data_block: bytes) -> bytes:
        decrypted_data = decrypt(
            self.private_key, int.from_bytes(data_block, byteorder="big")
        )
        unpadded_data = self.remove_padding(decrypted_data)
        return unpadded_data

    def decrypt(self, data: bytes) -> bytes:
        decrypted_data = b""
        for i in range(0, len(data), self.key_size):
            data_block = data[i : i + self.key_size]
            decrypted_data += self.decrypt_block(data_block)

        return decrypted_data


def main():
    message = "Hello Vizels you are the best homosexual" * 1
    publick_key, private_key = generate_keypair(2048)
    mode = ECB(publick_key, private_key)
    encrypted_message = mode.encrypt(message.encode("utf-8"))
    print(f"Encrypted data: {encrypted_message}")
    decrypted_message = mode.decrypt(encrypted_message)
    print(f"Decrypted data: {decrypted_message}")
    
    
if __name__ == "__main__":
    main()