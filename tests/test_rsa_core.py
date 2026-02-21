"""
Tests for the core RSA module: key generation, encryption, decryption, sign/verify.
"""

import pytest
from rsa_research.rsa_core import RSAKey, generate_keypair, encrypt, decrypt, sign, verify
from rsa_research.utils import gcd


class TestRSAKeyGeneration:
    def test_default_keypair_has_private_components(self):
        key = generate_keypair(bits=256)
        assert key.d is not None
        assert key.p is not None
        assert key.q is not None

    def test_modulus_is_product_of_primes(self):
        key = generate_keypair(bits=256)
        assert key.p * key.q == key.n

    def test_default_exponent_is_65537(self):
        key = generate_keypair(bits=256)
        assert key.e == 65537

    def test_custom_exponent(self):
        key = generate_keypair(bits=256, e=3)
        assert key.e == 3

    def test_private_exponent_valid(self):
        key = generate_keypair(bits=256)
        phi = (key.p - 1) * (key.q - 1)
        assert (key.e * key.d) % phi == 1

    def test_bit_length_approximate(self):
        key = generate_keypair(bits=256)
        # n should be close to 256 bits (within a few bits of the primes)
        assert 240 <= key.bit_length <= 260

    def test_distinct_primes(self):
        key = generate_keypair(bits=256, ensure_distinct_primes=True)
        assert key.p != key.q

    def test_bits_too_small_raises(self):
        with pytest.raises(ValueError):
            generate_keypair(bits=8)

    def test_even_exponent_raises(self):
        with pytest.raises(ValueError):
            generate_keypair(bits=256, e=4)

    def test_public_key_property(self):
        key = generate_keypair(bits=256)
        pub = key.public_key
        assert pub.d is None
        assert pub.n == key.n
        assert pub.e == key.e

    def test_repr(self):
        key = generate_keypair(bits=256)
        r = repr(key)
        assert "RSAKey" in r
        assert "has_private=True" in r


class TestEncryptDecrypt:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.key = generate_keypair(bits=256)

    def test_roundtrip_small_message(self):
        for m in [0, 1, 2, 42, 1000]:
            c = encrypt(m, self.key)
            assert decrypt(c, self.key) == m

    def test_roundtrip_large_message(self):
        m = self.key.n - 2
        c = encrypt(m, self.key)
        assert decrypt(c, self.key) == m

    def test_encrypt_requires_message_in_range(self):
        with pytest.raises(ValueError):
            encrypt(self.key.n, self.key)
        with pytest.raises(ValueError):
            encrypt(-1, self.key)

    def test_decrypt_requires_private_key(self):
        pub = self.key.public_key
        c = encrypt(42, pub)
        with pytest.raises(ValueError):
            decrypt(c, pub)

    def test_decrypt_requires_ciphertext_in_range(self):
        with pytest.raises(ValueError):
            decrypt(self.key.n, self.key)

    def test_different_messages_give_different_ciphertexts(self):
        c1 = encrypt(100, self.key)
        c2 = encrypt(200, self.key)
        assert c1 != c2


class TestSignVerify:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.key = generate_keypair(bits=256)

    def test_sign_verify_roundtrip(self):
        m = 12345
        sig = sign(m, self.key)
        assert verify(sig, self.key) == m

    def test_sign_requires_private_key(self):
        pub = self.key.public_key
        with pytest.raises(ValueError):
            sign(42, pub)

    def test_verify_wrong_message(self):
        sig = sign(100, self.key)
        assert verify(sig, self.key) != 999
