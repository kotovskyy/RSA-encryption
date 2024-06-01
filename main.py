"""Main module."""

from rsa.keys import generate_keypair, PublicKey, PrivateKey


def main():
    "Test the RSA implementation."
    public_key, private_key = generate_keypair(2048)
    public_key.export("public_key.pem")
    private_key.export("private_key.pem")

    public_key = PublicKey.load("public_key.pem")
    private_key = PrivateKey.load("private_key.pem")


if __name__ == "__main__":
    main()
