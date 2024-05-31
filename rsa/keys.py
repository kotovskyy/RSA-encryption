"""Classes and functions for RSA algorithm keys."""

from typing import Tuple
import sympy
from Crypto.PublicKey import RSA
import rsa.prime

DEFAULT_EXPONENT = 65537


class AbstractKey:
    """Interface class for RSA algorithm keys."""

    def __init__(self, e: int, n: int) -> None:
        self.e = e
        self.n = n

    def export(self, filename: str) -> None:
        """
        Export the RSA key to a file.

        Args:
            filename (str): The name of the file to export the key to.

        Raises:
            NotImplementedError: This method is not implemented yet.
        """
        raise NotImplementedError

    def load(self, filename: str) -> None:
        """
        Loads the RSA key from the specified file.

        Args:
            filename (str): The path to the file containing the RSA key.

        Raises:
            NotImplementedError: This method is not implemented yet.
        """
        raise NotImplementedError


class PublicKey(AbstractKey):
    """Public key for the RSA algorithm."""

    def export(self, filename: str) -> None:
        key = RSA.construct((self.n, self.e))
        with open(filename, "wb") as file:
            file.write(key.exportKey())

    def load(self, filename: str) -> None:
        with open(filename, "rb") as file:
            data = file.read()
        key = RSA.import_key(data)
        self.e = key.e
        self.n = key.n


class PrivateKey(AbstractKey):
    """Private key for the RSA algorithm."""

    def __init__(self, e: int, n: int, d: int, p: int, q: int) -> None:
        super().__init__(e, n)
        self.d = d
        self.p = p
        self.q = q

    def export(self, filename: str) -> None:
        key = RSA.construct((self.n, self.e, self.d, self.p, self.q))
        with open(filename, "wb") as file:
            file.write(key.exportKey())

    def load(self, filename: str) -> None:
        with open(filename, "rb") as file:
            data = file.read()
        key = RSA.import_key(data)
        self.e = key.e
        self.n = key.n
        self.d = key.d
        self.p = key.p
        self.q = key.q


def _are_primes_acceptable(p: int, q: int, length: int, accurate: bool = True) -> bool:
    """
    Check if the prime numbers p and q are acceptable.
    More specifically, check if the product of p and q has the desired bit length
    and p and q are not equal.
    """
    if p == q:
        return False
    if not accurate:
        return True

    n = p * q
    n_size = n.bit_length()
    return n_size == length


def generate_p_q(length: int, accurate: bool = True):
    """Generate two prime numbers p and q."""
    p = rsa.prime.generate_prime_number(length // 2)
    q = rsa.prime.generate_prime_number(length // 2)
    change_order = True
    while not _are_primes_acceptable(p, q, length, accurate):
        if change_order:
            p = rsa.prime.generate_prime_number(length // 2)
        else:
            q = rsa.prime.generate_prime_number(length // 2)
        change_order = not change_order

    return p, q


def generate_keypair(
    length: int, accurate: bool = True, exponent: int = DEFAULT_EXPONENT
) -> Tuple[PublicKey, PrivateKey]:
    """
    Generate a public-private key pair.
    """
    e = exponent
    p, q = generate_p_q(length, accurate)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    # find such d that (d * e) % phi_n = 1
    d = sympy.mod_inverse(e, phi_n)
    public_key = PublicKey(e, n)
    private_key = PrivateKey(e, n, d, p, q)

    return public_key, private_key


def main():
    """
    Generates a key pair, exports them to PEM files, and loads them back into memory.
    """
    public_key, private_key = generate_keypair(1024)
    public_key.export("public_key.pem")
    private_key.export("private_key.pem")
    public_key.load("public_key.pem")
    private_key.load("private_key.pem")


if __name__ == "__main__":
    main()
