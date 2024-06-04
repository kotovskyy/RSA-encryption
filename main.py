"""Main module."""

from rsa.keys import generate_keypair, PublicKey, PrivateKey
from rsa.png_rsa import PNG_RSA
from PIL import Image
import numpy as np
import io
from rsa.cipher_mode import ECB, CBC, CTR
from binascii import hexlify

def prettier_bytes(data: bytes, sep = ",") -> str:
    return hexlify(data, sep)

def png_raw_image():
    """
    >>> Image.open(filepath: str) - open the image
    
    >>> Image.convert(mode: str) - convert the image to a different mode, ex: "RGB"

    >>> Image.getdata() - get the RAW pixel data of the image
    
    If the image is in RGB mode, the data will be in the form:
    [R, G, B, R, G, B, ...]
    If the image is in RGBA mode, the data will be in the form:
    [R, G, B, A, R, G, B, A, ...]
    If the image is in Palette mode, the data will be in the form:
    [index, index, index, index, ...] 
    """
    image = Image.open("pngtools/images/penguin.png")
    image = image.convert("RGB")
    
    data = list(image.getdata())
    # FOR GESHUS
    # data_unpacked = []
    # for pixel in data:
    #   for pixel_value in pixel:
    #       data_unpacked.append(pixel_value)
    data_unpacked = [pixel_value for pixel in data for pixel_value in pixel]
    # print(f"Unpacked data: {data_unpacked}")
    data_unpacked = bytearray(data_unpacked)
    # print(f"RAW BYTES OF DATA: {prettier_bytes(data_unpacked)}")   
    
    # public_key = PublicKey.load("public_key.pem")
    # private_key = PrivateKey.load("private_key.pem")
    public_key, private_key = generate_keypair(128)

    additional_pad = False
    ecb = CBC(public_key, private_key, additional_pad)
    encrypted_data = ecb.encrypt(data_unpacked)
    # print(f"Encrypted data: {prettier_bytes(encrypted_data)}")
    decrypted_data = ecb.decrypt(encrypted_data)
    # print(f"Decrypted data: {prettier_bytes(decrypted_data)}")
    print(f"\nLen original data: {len(data_unpacked)}\nLen encrypted data: {len(encrypted_data)}\nLen decrypted data: {len(decrypted_data)}")
    initial_vector = encrypted_data[:ecb.key_size]
    #encrypted_data = encrypted_data[ecb.key_size:]
    image_part = encrypted_data[:len(data_unpacked)]
    # print(f"Encrypted part 1: {prettier_bytes(encrypted_part1)}")
    # print(f"Encrypted part 2: {prettier_bytes(encrypted_part2)}")
    
    key_size = ecb.key_size


    n_overflow_bytes = len(encrypted_data) - len(data_unpacked)
    print(f"\nImage part len: {len(image_part)}\nOverflow bytes: {n_overflow_bytes}")

    n_blocks = len(encrypted_data) // key_size
    print(f"\nNumber of blocks: {n_blocks}")

    remove_per_block = n_overflow_bytes // n_blocks
    print(f"\nRemove per block: {remove_per_block}")
    

    last_cut_len = n_overflow_bytes % n_blocks
    print(f"\nLast cut len: {last_cut_len}")
    
    if last_cut_len != 0:
        last_cut_data = encrypted_data[-last_cut_len:]
        encrypted_data = encrypted_data[:-last_cut_len]
    else:
        last_cut_data = b''

    encrypted_image_data = b''
    backlog = b''

    for i in range(0, len(encrypted_data), key_size):
        backlog += encrypted_data[i:i+remove_per_block]
        encrypted_image_data += encrypted_data[i+remove_per_block : i+key_size]

    backlog += last_cut_data


        
    print(f"Encrypted image data: {len(encrypted_image_data)}")
    print(f"Len cut off data: {len(backlog)}")
    
    new_image = Image.frombytes(image.mode, (image.width, image.height), encrypted_image_data)
    new_image.save("ecnrypted_pil.png")
    
    total_len = len(encrypted_image_data) + len(backlog) + len(initial_vector)
    print(f"Total len: {total_len}")
        
    block_ctr = 0
    encrypted_data = b''
    for i in range(0, len(encrypted_image_data), key_size-remove_per_block):
        encrypted_data += backlog[block_ctr * remove_per_block : block_ctr * remove_per_block + remove_per_block]
        encrypted_data += encrypted_image_data[i: i+key_size-remove_per_block]
        
        block_ctr = block_ctr + 1
    
    encrypted_data += last_cut_data#backlog[block_ctr * remove_per_block:]
    #encrypted_data = initial_vector + encrypted_data
            
    
    print(f"Len restored encrypted data: {len(encrypted_data)}")
    decrypted_data = ecb.decrypt(encrypted_data)
    print(f"Len decrypted data: {len(decrypted_data)}")
    
    restored_image = Image.frombytes(image.mode, (image.width, image.height), decrypted_data)
    restored_image.save("decrypted_pil.png")
    
    
    
    
def main():
    "Test the RSA implementation."
    public_key, private_key = generate_keypair(256)
    public_key.export("public_key.pem")
    private_key.export("private_key.pem")

    # public_key = PublicKey.load("public_key.pem")
    # private_key = PrivateKey.load("private_key.pem")

    png_rsa = PNG_RSA("pngtools/images/image2.png")
    png_rsa.set_public_key(public_key)
    png_rsa.set_private_key(private_key)
    encrypted_image = png_rsa.encrypt("ECB", False)
    decrypted_image = png_rsa.decrypt("ECB", False)
    

if __name__ == "__main__":
    # main()
    png_raw_image()
