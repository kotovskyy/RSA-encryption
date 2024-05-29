"""Functions for the RSA algorithm."""

import random

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
    msb_and_lsb = (1 << length - 1) | 1
    # Set the least significant bit to 1
    msb_and_lsb |= 1
    p |= msb_and_lsb

    return p


def main():
    """Run the test functions."""
    print(generate_prime_candidate(8))


if __name__ == "__main__":
    main()
