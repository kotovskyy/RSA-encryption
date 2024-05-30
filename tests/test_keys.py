import pytest
import sympy
import rsa.prime
import rsa.keys

@pytest.mark.parametrize("length", [8, 16, 32, 64, 128, 256, 512, 1024])
def test_prime_candidate_length(length: int):
    candidate = rsa.prime.generate_prime_candidate(length)
    assert candidate.bit_length() == length


@pytest.mark.parametrize("length", [8, 16, 32, 64, 128, 256, 512, 1024])
def test_generate_prime_number(length: int):
    prime = rsa.prime.generate_prime_number(length)
    assert sympy.isprime(prime)
    assert prime.bit_length() == length


@pytest.mark.parametrize("length", [8, 16, 32, 64, 128, 256, 512, 1024, 2048])
def test_generate_p_q_inaccurate(length: int):
    p, q = rsa.keys.generate_p_q(length, accurate=False)
    assert sympy.isprime(p)
    assert sympy.isprime(q)
    assert p != q
    assert p.bit_length() == length//2 
    assert q.bit_length() == length//2
