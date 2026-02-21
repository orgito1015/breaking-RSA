"""
Tests for utility functions: primality, modular arithmetic, integer roots, continued fractions.
"""

import pytest
from rsa_research.utils import (
    is_probable_prime,
    generate_prime,
    gcd,
    extended_gcd,
    modinv,
    isqrt,
    integer_nth_root,
    continued_fraction,
    convergents,
)


class TestIsProbablePrime:
    def test_small_primes(self):
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 97, 101]:
            assert is_probable_prime(p), f"{p} should be prime"

    def test_small_composites(self):
        for c in [1, 4, 6, 8, 9, 10, 15, 25, 49, 100]:
            assert not is_probable_prime(c), f"{c} should be composite"

    def test_zero_and_one_not_prime(self):
        assert not is_probable_prime(0)
        assert not is_probable_prime(1)

    def test_large_prime(self):
        # Known Mersenne prime M31 = 2^31 - 1
        assert is_probable_prime(2**31 - 1)

    def test_large_composite(self):
        # 2^31 - 1 is prime; 2^32 - 1 = 3 * 5 * 17 * 257 * 65537 is not
        assert not is_probable_prime(2**32 - 1)


class TestGeneratePrime:
    def test_generated_prime_is_prime(self):
        for bits in [16, 32, 64]:
            p = generate_prime(bits)
            assert is_probable_prime(p), f"generate_prime({bits}) returned composite {p}"

    def test_generated_prime_has_correct_bit_length(self):
        for bits in [16, 32, 64]:
            p = generate_prime(bits)
            assert p.bit_length() == bits

    def test_raises_on_too_small(self):
        with pytest.raises(ValueError):
            generate_prime(1)


class TestGCD:
    def test_basic(self):
        assert gcd(12, 8) == 4
        assert gcd(17, 13) == 1
        assert gcd(0, 5) == 5
        assert gcd(5, 0) == 5

    def test_commutativity(self):
        assert gcd(36, 24) == gcd(24, 36)


class TestExtendedGCD:
    def test_result_satisfies_bezout(self):
        for a, b in [(12, 8), (17, 13), (35, 15), (1, 1)]:
            g, x, y = extended_gcd(a, b)
            assert a * x + b * y == g
            assert g == gcd(a, b)


class TestModinv:
    def test_basic(self):
        assert modinv(3, 11) == 4  # 3*4 = 12 ≡ 1 (mod 11)
        assert modinv(7, 26) == 15  # 7*15 = 105 ≡ 1 (mod 26)

    def test_no_inverse_raises(self):
        with pytest.raises(ValueError):
            modinv(4, 8)  # gcd(4, 8) = 4 ≠ 1

    def test_result_in_range(self):
        inv = modinv(17, 100)
        assert 0 <= inv < 100
        assert (17 * inv) % 100 == 1


class TestIsqrt:
    def test_perfect_squares(self):
        for k in [0, 1, 4, 9, 16, 25, 100, 10000]:
            assert isqrt(k) ** 2 == k

    def test_non_perfect_squares(self):
        assert isqrt(2) == 1
        assert isqrt(8) == 2
        assert isqrt(10) == 3

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            isqrt(-1)


class TestIntegerNthRoot:
    def test_exact_cubes(self):
        for x in [0, 1, 8, 27, 64, 125, 1000]:
            r, exact = integer_nth_root(x, 3)
            assert exact
            assert r ** 3 == x

    def test_non_exact(self):
        r, exact = integer_nth_root(10, 3)
        assert not exact
        assert r == 2  # floor(10^(1/3))

    def test_square_root(self):
        r, exact = integer_nth_root(16, 2)
        assert exact
        assert r == 4

    def test_first_power(self):
        r, exact = integer_nth_root(42, 1)
        assert exact
        assert r == 42


class TestContinuedFraction:
    def test_simple_fraction(self):
        # 7/3 = [2; 3]
        coeffs = list(continued_fraction(7, 3))
        assert coeffs == [2, 3]

    def test_integer(self):
        # 5/1 = [5]
        assert list(continued_fraction(5, 1)) == [5]


class TestConvergents:
    def test_convergents_of_pi_approximation(self):
        # 355/113 is a classical convergent of pi; its convergents include 3/1 and 22/7
        convs = list(convergents(355, 113))
        # First convergent should be 3/1
        assert convs[0] == (3, 1)
        # One convergent should be 22/7
        assert (22, 7) in convs
