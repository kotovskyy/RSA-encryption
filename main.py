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
    public_key, private_key = generate_keypair(256)

    additional_pad = False
    ecb = ECB(public_key, private_key, additional_pad)
    encrypted_data = ecb.encrypt(data_unpacked)
    # print(f"Encrypted data: {prettier_bytes(encrypted_data)}")
    #decrypted_data = ecb.decrypt(encrypted_data)
    # print(f"Decrypted data: {prettier_bytes(decrypted_data)}")
    #print(f"\nLen original data: {len(data_unpacked)}\nLen encrypted data: {len(encrypted_data)}\nLen decrypted data: {len(decrypted_data)}")
    
    encrypted_part1 = encrypted_data[:len(data_unpacked)]
    encrypted_part2 = encrypted_data[len(data_unpacked):]
    # print(f"Encrypted part 1: {prettier_bytes(encrypted_part1)}")
    # print(f"Encrypted part 2: {prettier_bytes(encrypted_part2)}")
    print(f"\nLen encrypted part 1: {len(encrypted_part1)}\nLen encrypted part 2: {len(encrypted_part2)}")
    
    key_size = ecb.key_size


    n_overflow_bytes = len(encrypted_part2)
    print(f"\nNumber of overflow bytes: {n_overflow_bytes}")
    n_blocks = len(encrypted_data) // key_size
    print(f"\nNumber of blocks: {n_blocks}")
    remove_per_block = n_overflow_bytes // (n_blocks-1)
    print(f"\nRemove per block: {remove_per_block}")
    remove_from_last_block = n_overflow_bytes - remove_per_block * (n_blocks-1)
    print(f"\nRemove from last block: {remove_from_last_block}")
    
    cut_off_data = b''
    cut_encrypted_data = b''
    for i in range(0, len(encrypted_data), key_size):
        if i + key_size >= len(encrypted_data):
            cut_off_block = encrypted_data[i : i+remove_from_last_block]
            cut_ecnrypted_block = encrypted_data[i+remove_from_last_block : i+key_size]
        else:
            cut_off_block = encrypted_data[i : i+remove_per_block]
            cut_ecnrypted_block = encrypted_data[i+remove_per_block : i+key_size]
            
        cut_off_data += cut_off_block
        cut_encrypted_data += cut_ecnrypted_block
        
    print(f"Len cut encrypted data: {len(cut_encrypted_data)}")
    print(f"Len cut off data: {len(cut_off_data)}")
    new_image = Image.frombytes(image.mode, (image.width, image.height), cut_encrypted_data)
    new_image.save("ecnrypted_pil.png")
    
    total_len = len(cut_encrypted_data) + len(cut_off_data)
    print(f"Total len: {total_len}")
        
    block_ctr = 0
    encrypted_data = b''
    for i in range(0, len(cut_encrypted_data), key_size-remove_per_block):
        if block_ctr == n_blocks-1:
            encrypted_block = cut_off_data[block_ctr*remove_per_block : ]
            encrypted_block += cut_encrypted_data[i:]
        else:
            encrypted_block = cut_off_data[block_ctr*remove_per_block : (block_ctr+1)*remove_per_block]
            encrypted_block += cut_encrypted_data[i: i+key_size-remove_per_block]
        
        block_ctr += 1
        encrypted_data += encrypted_block
        
            
    
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
