"""Classes and functions for RSA algorithm keys."""

from typing import Tuple
import sympy
import rsa.prime

DEFAULT_EXPONENT = 65537


class AbstractKey:
    """Interface class for RSA algorithm keys."""

    def __init__(self, e: int, n: int) -> None:
        self.e = e
        self.n = n


class PublicKey(AbstractKey):
    """Public key for the RSA algorithm."""


class PrivateKey(AbstractKey):
    """Private key for the RSA algorithm."""

    def __init__(self, e: int, n: int, d: int) -> None:
        super().__init__(e, n)
        self.d = d


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
    private_key = PrivateKey(e, n, d)

    return public_key, private_key
