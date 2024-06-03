"""Block cipher modes of operation for RSA encryption."""

import random
from rsa.keys import PublicKey, PrivateKey, generate_keypair
from rsa.rsa_utils import encrypt, decrypt
from binascii import hexlify

class BaseMode:
    """Interface class for block cipher modes of operation."""

    def __init__(self, publick_key: PublicKey, private_key: PrivateKey):
        self.public_key = publick_key
        self.private_key = private_key
        self.key_size = (publick_key.n.bit_length() + 7) // 8
        self.block_size = self.key_size - 11  # min 11 bytes for padding

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt the data."""
        raise NotImplementedError

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt the data."""
        raise NotImplementedError

    def add_padding(self, data_block: bytes) -> bytes:
        """
        Add padding to the data block.
        Minimum padding size is 11 bytes. The padding is in the form:
        `00 02 [random non-zero bytes] 00 [data_block]`

        Args:
            - `data_block: bytes`: The data block to pad.

        Returns:
            - `bytes`: The padded data block.

        Raises:
            - `ValueError`: If the data is too long.
        """
        if len(data_block) > self.block_size:
            raise ValueError(
                f"Data is too long. Max. data size is {self.block_size} bytes"
            )

        padding_size = self.key_size - len(data_block) - 3
        padding = (
            b"\x00"
            + b"\x02"
            + random.randbytes(padding_size).replace(b"\x00", b"\x01")
            + b"\x00"
        )

        return padding + data_block

    def encrypt_block(self, data_block: bytes, additional_pad: bool = True) -> bytes:
        """
        Encrypt a single block of data. The block size is determined by the key size.

        Args:
            - `data_block: bytes`: The data block to encrypt.

        Returns:
            - `bytes`: The encrypted data block.
        """
        if additional_pad:
            data_block = self.add_padding(data_block)
        return encrypt(self.public_key, int.from_bytes(data_block, byteorder="big"))

    def remove_padding(self, data_block: bytes):
        """
        Remove the padding from the data block.

        Args:
            - `data_block: bytes`: The data block to remove padding from.

        Returns:
            - `bytes`: The data block without padding.
        """
        padding = data_block[0:2]
        if padding != b"\x00\x02":
            raise ValueError("Invalid padding")
        padding_end = data_block.find(b"\x00", 2)

        return data_block[padding_end + 1 :]

    def decrypt_block(self, data_block: bytes, additional_pad: bool = True) -> bytes:
        """
        Decrypt a single block of data. The block size is determined by the key size.

        Args:
            - `data_block: bytes`: The data block to decrypt.

        Returns:
            - `bytes`: The decrypted data block.
        """
        decrypted_data = decrypt(
            self.private_key, int.from_bytes(data_block, byteorder="big")
        )
        if additional_pad:
            decrypted_data = self.remove_padding(decrypted_data)
        return decrypted_data


class ECB(BaseMode):
    """Electronic Codebook (ECB) mode for RSA encryption."""

    def encrypt(self, data: bytes, additional_pad: bool = True) -> bytes:
        """
        Encrypt the data using the ECB mode.

        Args:
            - `data: bytes`: The data to encrypt.

        Returns:
            - `bytes`: The encrypted data.
        """
        self.block_size = self.key_size - 11 if additional_pad else self.key_size - 1
        encrypted_data = b""
        for i in range(0, len(data), self.block_size):
            data_block = data[i : i + self.block_size]
            if not additional_pad:
                data_block = b"\x01" + data_block
                
            encrypted_block = self.encrypt_block(data_block, additional_pad)
            encrypted_data += encrypted_block

        return encrypted_data

    def decrypt(self, data: bytes, additional_pad: bool = True) -> bytes:
        """
        Decrypt the data using the ECB mode.

        Args:
            - `data: bytes`: The data to decrypt.

        Returns:
            - `bytes`: The decrypted data.
        """
        decrypted_data = b""
        for i in range(0, len(data), self.key_size):
            data_block = data[i : i + self.key_size]
            decrypted_block = self.decrypt_block(data_block, additional_pad)
            if not additional_pad:
                if i + self.key_size >= len(data):
                    decrypted_block = decrypted_block.lstrip(b"\x00")
                decrypted_block = decrypted_block[1:]
                    
            decrypted_data += decrypted_block

        return decrypted_data


class CBC(BaseMode):
    """Cipher Block Chaining (CBC) mode for RSA encryption."""

    def encrypt(self, data: bytes, additional_pad: bool = True) -> bytes:
        """
        Encrypt the data using the CBC mode.

        Args:
            - `data: bytes`: The data to encrypt.

        Returns:
            - `bytes`: The encrypted data.
        """
        self.block_size = self.key_size - 11 if additional_pad else self.key_size - 1
        initial_vector = random.randbytes(self.key_size)
        encrypted_data = b"" + initial_vector
        for i in range(0, len(data), self.block_size):
            data_block = data[i : i + self.block_size]
            if not additional_pad:
                data_block = b"\x01" + data_block
                if i + self.block_size >= len(data):
                    data_block = b'\x00' * (self.key_size - len(data_block)) + data_block
                    
            encrypted_block = self.encrypt_block(
                bytes(b1 ^ b2 for b1, b2 in zip(data_block, initial_vector)),
                additional_pad,
            )
            encrypted_data += encrypted_block
            initial_vector = encrypted_block

        return encrypted_data

    def decrypt(self, data: bytes, additional_pad: bool = True) -> bytes:
        """
        Decrypt the data using the CBC mode.

        Args:
            - `data: bytes`: The data to decrypt.

        Returns:
            - `bytes`: The decrypted data.
        """
        initial_vector = data[0 : self.key_size]
        decrypted_data = b""
        for i in range(self.key_size, len(data), self.key_size):
            data_block = data[i : i + self.key_size]
            decrypted_block = self.decrypt_block(data_block, additional_pad)
            decrypted_block = bytes(
                b1 ^ b2 for b1, b2 in zip(decrypted_block, initial_vector)
            )
            if not additional_pad:
                if i + self.key_size >= len(data):
                    decrypted_block = decrypted_block.lstrip(b"\x00")
                decrypted_block = decrypted_block[1:]
            
     
            initial_vector = data_block
            decrypted_data += decrypted_block

        return decrypted_data


class CTR(BaseMode):
    """Counter (CTR) mode for RSA encryption."""
    def encrypt(self, data: bytes, additional_pad: bool = False) -> bytes:
        """
        Encrypt the data using the CBC mode.

        Args:
            - `data: bytes`: The data to encrypt.

        Returns:
            - `bytes`: The encrypted data.
        """
        self.block_size = self.key_size - 11 if additional_pad else self.key_size
        nonce = random.randbytes(self.block_size)
        encrypted_data = b"" + nonce
        for i in range(0, len(data), self.block_size):
            data_block = data[i : i + self.block_size]
            encrypted_counter = self.encrypt_block(nonce, additional_pad)
            if len(data_block) != self.block_size:
                data_block = b"\x00" * (self.block_size - len(data_block)) + data_block
            encrypted_block = bytes(b1 ^ b2 for b1, b2 in zip(data_block, encrypted_counter))
            print(f"Encrypted block len: {len(encrypted_block)}")
            encrypted_data += encrypted_block
            nonce = int.to_bytes(int.from_bytes(nonce, byteorder="big") + 1, self.block_size, byteorder="big")

        return encrypted_data

    def decrypt(self, data: bytes, additional_pad: bool = False) -> bytes:
        """
        Decrypt the data using the CBC mode.

        Args:
            - `data: bytes`: The data to decrypt.

        Returns:
            - `bytes`: The decrypted data.
        """
        self.block_size = self.key_size - 11 if additional_pad else self.key_size
        nonce = data[0 : self.block_size]
        decrypted_data = b""
        for i in range(self.block_size, len(data), self.key_size):
            data_block = data[i : i + self.key_size]
            encrypted_counter = self.encrypt_block(nonce, additional_pad)
            decrypted_block = bytes(b1 ^ b2 for b1, b2 in zip(data_block, encrypted_counter))
            print(f"Decrypted block len: {len(decrypted_block)}")
            if i + self.key_size >= len(data) and not additional_pad:
                decrypted_block = decrypted_block.lstrip(b"\x00")
            decrypted_data += decrypted_block
            nonce = int.to_bytes(int.from_bytes(nonce, byteorder="big") + 1, self.block_size, byteorder="big")

        return decrypted_data


def main():
    # key 32 bit
    public_key, private_key = generate_keypair(32)
    """Test the modes of operation."""
    message = b"\x00 Hello vizels \x00" * 5
    # public_key = PublicKey.load("public_key.pem")
    # private_key = PrivateKey.load("private_key.pem")
    mode = CBC(public_key, private_key)
    encrypted_message = mode.encrypt(message, False)
    print(f"Encrypted data: {encrypted_message}")
    decrypted_message = mode.decrypt(encrypted_message, False)
    print(f"Decrypted data: {decrypted_message}")


if __name__ == "__main__":
    main()
