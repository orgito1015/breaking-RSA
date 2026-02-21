"""
Utility functions for RSA research: primality testing, modular arithmetic, etc.
"""

import math
import random
from typing import Tuple


# ---------------------------------------------------------------------------
# Primality testing
# ---------------------------------------------------------------------------

def is_probable_prime(n: int, rounds: int = 20) -> bool:
    """
    Miller-Rabin probabilistic primality test.

    Args:
        n: Integer to test.
        rounds: Number of witness rounds (higher → lower false-positive rate).

    Returns:
        True if n is probably prime, False if definitely composite.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a random probable prime of exactly *bits* bits.

    Args:
        bits: Desired bit-length (must be >= 2).

    Returns:
        A probable prime p with p.bit_length() == bits.
    """
    if bits < 2:
        raise ValueError("bits must be at least 2")
    while True:
        # Ensure the top bit is set (so the number has exactly `bits` bits)
        # and the bottom bit is set (so the number is odd).
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


# ---------------------------------------------------------------------------
# Modular arithmetic helpers
# ---------------------------------------------------------------------------

def gcd(a: int, b: int) -> int:
    """Return the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.

    Returns:
        (g, x, y) such that a*x + b*y == g == gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def modinv(a: int, m: int) -> int:
    """
    Modular multiplicative inverse of a mod m.

    Args:
        a: Integer whose inverse is desired.
        m: Modulus.

    Returns:
        x such that (a * x) % m == 1.

    Raises:
        ValueError: If gcd(a, m) != 1 (inverse does not exist).
    """
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g}")
    return x % m


def isqrt(n: int) -> int:
    """Integer square root (floor)."""
    if n < 0:
        raise ValueError("Square root not defined for negative numbers")
    if n == 0:
        return 0
    x = int(math.isqrt(n))
    return x


def integer_nth_root(n: int, k: int) -> Tuple[int, bool]:
    """
    Compute the integer k-th root of n.

    Returns:
        (root, exact) where root = floor(n^(1/k)) and exact is True if
        root**k == n.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if k <= 0:
        raise ValueError("k must be positive")
    if n == 0:
        return 0, True
    if k == 1:
        return n, True

    # Newton's method
    x = int(round(n ** (1.0 / k)))
    # Adjust for floating-point errors
    for delta in (-2, -1, 0, 1, 2):
        candidate = x + delta
        if candidate > 0 and candidate ** k == n:
            return candidate, True

    # Binary search for floor
    lo, hi = 1, min(n, 1 << ((n.bit_length() + k - 1) // k + 1))
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo, lo ** k == n


# ---------------------------------------------------------------------------
# Continued fractions
# ---------------------------------------------------------------------------

def continued_fraction(numerator: int, denominator: int):
    """
    Generate the continued fraction coefficients [a0; a1, a2, ...] for
    numerator/denominator.

    Yields:
        Integer coefficients a_i.
    """
    while denominator:
        q = numerator // denominator
        yield q
        numerator, denominator = denominator, numerator - q * denominator


def convergents(numerator: int, denominator: int):
    """
    Generate the convergents (p_i/q_i) of the continued fraction for
    numerator/denominator.

    Yields:
        (p, q) pairs representing convergents p/q.
    """
    p_prev, p_curr = 0, 1
    q_prev, q_curr = 1, 0
    for a in continued_fraction(numerator, denominator):
        p_prev, p_curr = p_curr, a * p_curr + p_prev
        q_prev, q_curr = q_curr, a * q_curr + q_prev
        yield p_curr, q_curr
