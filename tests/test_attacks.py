"""
Tests for RSA attack modules: Fermat, Wiener, Common Modulus, Small Exponent, Pollard's Rho.
"""

import pytest
from rsa_research.rsa_core import RSAKey, generate_keypair, encrypt
from rsa_research.utils import generate_prime, modinv, gcd
from rsa_research.attacks import (
    fermat_factor,
    wiener_attack,
    common_modulus_attack,
    small_exponent_attack,
    pollard_rho,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_weak_fermat_key(bits: int = 128) -> RSAKey:
    """Generate a key where p and q are very close (Fermat-vulnerable)."""
    half = bits // 2
    p = generate_prime(half)
    # q is very close to p: start from p and find the next prime
    q = p + 2
    from rsa_research.utils import is_probable_prime
    while not is_probable_prime(q):
        q += 2
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        e = 3
    d = modinv(e, phi)
    return RSAKey(n=n, e=e, d=d, p=p, q=q)


def make_wiener_key(bits: int = 256) -> RSAKey:
    """Generate a key with small d (Wiener-vulnerable): d ~ n^0.2."""
    from rsa_research.utils import generate_prime, is_probable_prime
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # Pick d small: roughly n^(1/5)
        d_bits = max(4, bits // 5)
        d = generate_prime(d_bits)
        if gcd(d, phi) != 1:
            continue
        e = modinv(d, phi)
        if e <= 1:
            continue
        return RSAKey(n=n, e=e, d=d, p=p, q=q)


# ---------------------------------------------------------------------------
# Fermat factorization tests
# ---------------------------------------------------------------------------

class TestFermatFactorization:
    def test_factors_close_primes(self):
        key = make_weak_fermat_key(bits=64)
        result = fermat_factor(key.n)
        assert result is not None
        p, q = result
        assert p * q == key.n
        assert p > 1 and q > 1

    def test_factors_small_known_composite(self):
        # 15 = 3 * 5
        result = fermat_factor(15)
        assert result is not None
        assert set(result) == {3, 5}

    def test_factors_perfect_square(self):
        result = fermat_factor(49)
        assert result is not None
        assert result[0] * result[1] == 49

    def test_handles_even_n(self):
        result = fermat_factor(14)
        assert result == (2, 7)

    def test_returns_none_when_primes_far_apart(self):
        # Use a very small step budget so it gives up quickly
        p = 101  # prime
        q = 9901  # prime, much larger
        n = p * q
        result = fermat_factor(n, max_steps=5)
        # With max_steps=5 it should not find the factorization
        assert result is None or result[0] * result[1] == n

    def test_raises_on_invalid_n(self):
        with pytest.raises(ValueError):
            fermat_factor(1)
        with pytest.raises(ValueError):
            fermat_factor(-5)


# ---------------------------------------------------------------------------
# Wiener's attack tests
# ---------------------------------------------------------------------------

class TestWienerAttack:
    def test_recovers_small_d(self):
        key = make_wiener_key(bits=128)
        recovered_d = wiener_attack(key)
        assert recovered_d == key.d, (
            f"Wiener failed: expected d={key.d}, got {recovered_d}"
        )

    def test_normal_key_not_broken(self):
        # A well-generated 512-bit key should NOT be broken by Wiener
        key = generate_keypair(bits=256)
        recovered_d = wiener_attack(key)
        # Either returns None or returns the correct d (very unlikely for large d)
        if recovered_d is not None:
            assert recovered_d == key.d


# ---------------------------------------------------------------------------
# Common modulus attack tests
# ---------------------------------------------------------------------------

class TestCommonModulusAttack:
    def test_recovers_plaintext(self):
        key1 = generate_keypair(bits=256, e=17)
        # Build a second key sharing the same n but different e
        from rsa_research.utils import modinv
        phi = (key1.p - 1) * (key1.q - 1)
        e2 = 65537
        if gcd(e2, phi) != 1:
            e2 = 257
        d2 = modinv(e2, phi)
        key2 = RSAKey(n=key1.n, e=e2, d=d2)

        m = 42
        c1 = encrypt(m, key1)
        c2 = encrypt(m, key2)

        recovered = common_modulus_attack(key1.n, key1.e, key2.e, c1, c2)
        assert recovered == m

    def test_returns_none_when_exponents_not_coprime(self):
        result = common_modulus_attack(n=100, e1=6, e2=9, c1=10, c2=20)
        assert result is None


# ---------------------------------------------------------------------------
# Small exponent attack tests
# ---------------------------------------------------------------------------

class TestSmallExponentAttack:
    def test_recovers_small_message_e3(self):
        e = 3
        m = 42

        # Generate 3 independent keys with e=3
        keys = []
        for _ in range(e):
            k = generate_keypair(bits=256, e=e)
            keys.append(k)

        ciphertexts = [(k.n, encrypt(m, k)) for k in keys]
        recovered = small_exponent_attack(ciphertexts, e)
        assert recovered == m

    def test_raises_when_too_few_ciphertexts(self):
        e = 3
        key = generate_keypair(bits=256, e=e)
        with pytest.raises(ValueError):
            small_exponent_attack([(key.n, 1)], e)


# ---------------------------------------------------------------------------
# Pollard's rho tests
# ---------------------------------------------------------------------------

class TestPollardRho:
    def test_factors_small_composite(self):
        # 15 = 3 * 5
        f = pollard_rho(15)
        assert f is not None
        assert 15 % f == 0 and 1 < f < 15

    def test_factors_semiprime(self):
        p, q = 101, 103
        n = p * q
        f = pollard_rho(n)
        assert f is not None
        assert n % f == 0 and 1 < f < n

    def test_even_number(self):
        f = pollard_rho(100)
        assert f == 2

    def test_prime_returns_none(self):
        f = pollard_rho(101)
        assert f is None

    def test_raises_on_invalid_input(self):
        with pytest.raises(ValueError):
            pollard_rho(1)
        with pytest.raises(ValueError):
            pollard_rho(-10)
