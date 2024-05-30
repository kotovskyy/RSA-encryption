"""Test functions for the RSA algorithm."""

from rsa.keys import PublicKey, PrivateKey, generate_keypair


def decrypt(private_key: PrivateKey, encrypted_message: int) -> int:
    """
    Decrypt a message using a private key.

    Args:
        - `private_key: PrivateKey`: The private key.
        - `encrypted_message: int`: The message to decrypt.

    Returns:
        - `int`: The decrypted message.

    Example:
    >>> private_key = PrivateKey(65537, 3233, 2753)
    >>> encrypted_message = 855
    >>> decrypted_message = decrypt(private_key, encrypted_message)
    >>> print(decrypted_message)
    1234
    """
    return pow(encrypted_message, private_key.d, private_key.n)


def encrypt(public_key: PublicKey, message: int) -> int:
    """
    Encrypt a message using a public key.

    Args:
        - `public_key: PublicKey`: The public key.
        - `message: int`: The message to encrypt.

    Returns:
        - `int`: The encrypted message.

    Example:
    >>> public_key = PublicKey(65537, 3233)
    >>> message = 1234
    >>> encrypted_message = encrypt(public_key, message)
    >>> print(encrypted_message)
    855
    """
    return pow(message, public_key.e, public_key.n)


def text_to_int(text: str) -> int:
    """Convert a string to an integer."""
    return int.from_bytes(text.encode("utf-8"), byteorder="big")


def int_to_text(number: int) -> str:
    """Convert an integer to a string."""
    return number.to_bytes((number.bit_length() + 7) // 8, byteorder="big").decode(
        "utf-8"
    )


def encrypt_text(public_key: PublicKey, message: str) -> int:
    """Encrypt a text message using a public key."""
    message = text_to_int(message)
    return encrypt(public_key, message)


def decrypt_text(private_key: PrivateKey, message: int) -> str:
    """Decrypt a text message using a private key."""
    message = decrypt(private_key, message)
    return int_to_text(message)


def main():
    """Run the test functions."""
    public_key, private_key = generate_keypair(2048)
    message = "Hello there!"
    encrypted_message = encrypt_text(public_key, message)
    decrypted_message = decrypt_text(private_key, encrypted_message)
    print(f"Original message: {message}")
    print(f"Encrypted message: {encrypted_message}")
    print(f"Decrypted message: {decrypted_message}")


if __name__ == "__main__":
    main()