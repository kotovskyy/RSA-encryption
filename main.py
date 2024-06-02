"""Main module."""

from rsa.keys import generate_keypair, PublicKey, PrivateKey
from rsa.png_rsa import PNG_RSA

def main():
    "Test the RSA implementation."
    public_key, private_key = generate_keypair(2048)
    public_key.export("public_key.pem")
    private_key.export("private_key.pem")

    public_key = PublicKey.load("public_key.pem")
    private_key = PrivateKey.load("private_key.pem")

    png_rsa = PNG_RSA("pngtools/images/image3.png")
    png_rsa.set_public_key(public_key)
    png_rsa.set_private_key(private_key)
    encrypted_image = png_rsa.encrypt("ECB", False)
    decrypted_image = png_rsa.decrypt("ECB", False)
    

if __name__ == "__main__":
    main()
