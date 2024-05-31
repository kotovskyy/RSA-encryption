"""PNG_RSA module for encrypting and decrypting PNG images using RSA."""

from pngtools.png.PNG import PNG
from pngtools.png.chunks import Chunk
from rsa.keys import PublicKey, PrivateKey, generate_keypair
from rsa.cipher_mode import ECB, CBC


class PNG_RSA:
    """PNG_RSA interface for encrypting and decrypting PNG images using RSA."""

    def __init__(self, filename: str) -> None:
        self.image = PNG(filename)
        self.key_size = None
        self.public_key = None
        self.private_key = None

    def generate_keypair(self, key_size: int) -> None:
        """
        Generate a keypair for the RSA algorithm.

        Args:
            - `key_size: int`: The size of the key in bits.
        """
        self.public_key, self.private_key = generate_keypair(key_size)
        self.key_size = key_size

    def get_public_key(self) -> PublicKey:
        """Get the RSA public key."""
        return self.public_key

    def get_private_key(self) -> PrivateKey:
        """Get the RSA private key."""
        return self.private_key

    def set_public_key(self, key: PublicKey) -> None:
        """Initialize the RSA public key with a given key."""
        self.public_key = key
        self.key_size = key.n.bit_length()

    def set_private_key(self, key: PrivateKey) -> None:
        """Initialize the RSA private key with a given key."""
        self.private_key = key
        self.key_size = key.n.bit_length()

    def _choose_mode(self, method: str):
        """
        Choose the mode of operation for the RSA algorithm.

        Raises:
            - `ValueError`: If the mode is invalid.
        """
        if method == "ECB":
            return ECB(self.public_key, self.private_key)
        elif method == "CBC":
            return CBC(self.public_key, self.private_key)
        raise ValueError("Invalid mode")

    def _get_IDAT(self) -> Chunk:
        """
        Get the IDAT chunk from the image.

        Returns:
            - `Chunk`: The IDAT chunk.

        Raises:
            - `ValueError`: If the IDAT chunk is not found.
        """
        self.image.merge_IDAT()
        for chunk in self.image.chunks:
            if chunk.name == "IDAT":
                return chunk
        raise ValueError("IDAT chunk not found")

    def replace_chunk(self, old_chunk: Chunk, new_chunk: Chunk) -> None:
        """Replace `old_chunk` with `new_chunk` in the image."""
        index = self.image.chunks.index(old_chunk)
        self.image.chunks.remove(old_chunk)
        self.image.chunks.insert(index, new_chunk)

    def encrypt(self, method: str = "ECB") -> bytes:
        """
        Encrypt the image using the RSA algorithm and given method.
        Methods correspond to the modes of operation in the RSA algorithm.

        Args:
            - `method: str`: The method to use for encryption.
            Available methods: "ECB", "CBC".

        Returns:
            - `bytes`: The encrypted data.
        """
        idat_chunk = self._get_IDAT()

        mode = self._choose_mode(method)

        encrypted_data = mode.encrypt(idat_chunk.data)
        new_chunk = Chunk(
            name="IDAT",
            size=len(encrypted_data),
            data=encrypted_data,
            crc=PNG._calculateCRC("IDAT", encrypted_data),
        )

        self.replace_chunk(idat_chunk, new_chunk)
        self.image.saveFile("encrypted.png", True)

        return encrypted_data

    def decrypt(self, method: str = "ECB") -> bytes:
        """
        Decrypt the image using the RSA algorithm and given method.
        Methods correspond to the modes of operation in the RSA algorithm.
        Available methods: "ECB", "CBC".

        Important: Make sure that you decrypt the image using the same method
        that was used to encrypt it.

        Args:
            - `method: str`: The method to use for decryption.
            Available methods: "ECB", "CBC".

        Returns:
            - `bytes`: The decrypted data.
        """
        idat_chunk = self._get_IDAT()
        mode = self._choose_mode(method)

        decrypted_data = mode.decrypt(idat_chunk.data)
        new_chunk = Chunk(
            name="IDAT",
            size=len(decrypted_data),
            data=decrypted_data,
            crc=PNG._calculateCRC("IDAT", decrypted_data),
        )

        self.replace_chunk(idat_chunk, new_chunk)
        self.image.saveFile("decrypted.png", True)

        return decrypted_data


def main():
    """Test the PNG_RSA class."""
    filepath = "pngtools/images/image2.png"
    encryptor = PNG_RSA(filepath)
    encryptor.generate_keypair(2048)
    _ = encryptor.encrypt("CBC")
    _ = encryptor.decrypt("CBC")


if __name__ == "__main__":
    main()
