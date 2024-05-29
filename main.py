"""Test functions for the RSA algorithm."""

import random
from typing import Tuple
import sympy
from keys import PublicKey, PrivateKey


DEFAULT_EXPONENT = 65537


def generate_prime_candidate(length: int) -> int:
    """
    Generate a prime candidate number.
    The number is odd and has exactly `length` bits.

    Args:
        - `length: int`: The number of bits the prime should have.

    Returns:
        - `int`: The prime candidate number.

    Example:
    >>> length = 8
    >>> candidate = generate_prime_candidate(length)
    >>> print(bin(candidate))
    '0b11101011' # Example output, actual output will vary
    """
    p = random.getrandbits(length)
    # Set the most significant bit to 1
    msb_and_lsb = 1 << length - 1
    # Set the least significant bit to 1
    msb_and_lsb |= 1
    p |= msb_and_lsb

    return p


def generate_prime_number(length: int) -> int:
    """
    Generate a prime number.

    Args:
        - `length: int`: The number of bits the prime should have.

    Returns:
        - `int`: The prime number.

    Example:
    >>> length = 8
    >>> prime = generate_prime_number(length)
    >>> print(bin(prime))
    '0b11000101' # 197, example output, actual output will vary
    """
    while True:
        p = generate_prime_candidate(length)
        if sympy.isprime(p):
            return p


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

    n_size = p.bit_length() + q.bit_length()
    return n_size == length


def generate_p_q(length: int, accurate: bool = True):
    """Generate two prime numbers p and q."""
    p, q = 1, 1
    change_order = True
    while not _are_primes_acceptable(p, q, length, accurate):
        if change_order:
            p = generate_prime_number(length // 2)
        else:
            q = generate_prime_number(length // 2)
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


def main():
    """Run the test functions."""
    public_key, private_key = generate_keypair(2048)


if __name__ == "__main__":
    main()
