"""PNG_RSA module for encrypting and decrypting PNG images using RSA."""

from pngtools.png.PNG import PNG
from pngtools.png.chunks import Chunk
from rsa.keys import PublicKey, PrivateKey, generate_keypair
from rsa.cipher_mode import ECB, CBC, CTR, BaseMode
from PIL import Image

class PNG_RSA:
    """PNG_RSA interface for encrypting and decrypting PNG images using RSA."""

    def __init__(self, filename: str, pkcs1_pad: bool = True) -> None:
        self.image = PNG(filename)
        self.key_size = None
        self.public_key = None
        self.private_key = None
        self.additional_pad = pkcs1_pad
        
    def get_image_raw_data(self) -> bytes:
        """
        Get the raw data of the image's pixels.
        
        Returns:
            - `bytes`: The raw data of the image's pixels.
        """
        img_path = self.image.file
        image = Image.open(img_path)
        image = image.convert("RGB")
        
        data = list(image.getdata())
        data_unpacked = [pixel_value for pixel in data for pixel_value in pixel]
        data_unpacked = bytearray(data_unpacked)
        
        return data_unpacked, image.width, image.height

    def _encrypt_raw_image(self, mode: BaseMode):
        data_unpacked, img_width, img_height = self.get_image_raw_data()
        encrypted_data = mode.encrypt(data_unpacked)
        image_part = encrypted_data[:len(data_unpacked)]
        n_overflow_bytes = len(encrypted_data) - len(data_unpacked)
        n_blocks = len(encrypted_data) // self.key_size
        remove_per_block = n_overflow_bytes // n_blocks
        last_cut_len = n_overflow_bytes % n_blocks
        
        if last_cut_len != 0:
            last_cut_data = encrypted_data[-last_cut_len:]
            encrypted_data = encrypted_data[:-last_cut_len]
        else:
            last_cut_data = b''

        backlog = b''               # data cut from every encrypted block
        encrypted_image_data = b''  # encrypted data to be stored in the image's IDAT
        
        print(f"\nNumber of blocks: {n_blocks}")
        print(f"\nRemove per block: {remove_per_block}")
        print(f"Self.key_size = {self.key_size}")
        for i in range(0, len(encrypted_data), self.key_size):
            print(f"i = {i}")
            backlog += encrypted_data[i:i+remove_per_block]
            encrypted_image_data += encrypted_data[i+remove_per_block : i+self.key_size]

        backlog += last_cut_data
        
        print(len(encrypted_image_data))
        new_image = Image.frombytes("RGB", (img_width, img_height), encrypted_image_data)
        new_image.save("ecnrypted_pil.png")

        return encrypted_data
    
    def _encrypt_image(self, mode: BaseMode):
        idat_chunk = self._get_IDAT()
        
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
        
    def generate_keypair(self, key_size: int) -> None:
        """
        Generate a keypair for the RSA algorithm.

        Args:
            - `key_size: int`: The size of the key in bits.
        """
        self.public_key, self.private_key = generate_keypair(key_size)
        self.key_size = (key_size + 7) // 8

    def get_public_key(self) -> PublicKey:
        """Get the RSA public key."""
        return self.public_key

    def get_private_key(self) -> PrivateKey:
        """Get the RSA private key."""
        return self.private_key

    def set_public_key(self, key: PublicKey) -> None:
        """Initialize the RSA public key with a given key."""
        self.public_key = key
        self.key_size = (key.n.bit_length() + 7) // 8

    def set_private_key(self, key: PrivateKey) -> None:
        """Initialize the RSA private key with a given key."""
        self.private_key = key
        self.key_size = (key.n.bit_length() + 7) // 8

    def _choose_mode(self, method: str):
        """
        Choose the mode of operation for the RSA algorithm.

        Raises:
            - `ValueError`: If the mode is invalid.
        """
        if method == "ECB":
            return ECB(self.public_key, self.private_key, self.additional_pad)
        if method == "CTR":
            return CTR(self.public_key, self.private_key, self.additional_pad)
        if method == "CBC":
            return CBC(self.public_key, self.private_key, self.additional_pad)
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

    def encrypt(self, method: str = "ECB", make_showable: bool = True) -> bytes:
        """
        Encrypt the image using the RSA algorithm and given method.
        Methods correspond to the modes of operation in the RSA algorithm.

        Args:
            - `method: str`: The method to use for encryption.
            Available methods: "ECB", "CBC".

        Returns:
            - `bytes`: The encrypted data.
        """
        mode = self._choose_mode(method)
        if make_showable:
            encrypted_data = self._encrypt_raw_image(mode)
        else:
            encrypted_data = self._encrypt_image(mode)
            
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
