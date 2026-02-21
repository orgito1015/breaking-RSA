"""
Fermat's Factorization Method.

Works well when the two prime factors p and q are close to each other, i.e.
|p - q| is small relative to sqrt(n).  In that case n ≈ ((p+q)/2)^2 and
Fermat's method finds the factorization quickly.

Complexity: O(|p - q|) iterations for primes of similar size.
"""

from ..utils import isqrt
from typing import Optional, Tuple


def fermat_factor(n: int, max_steps: int = 1_000_000) -> Optional[Tuple[int, int]]:
    """
    Attempt to factor n using Fermat's method.

    The algorithm searches for integers a, b such that n = a^2 - b^2 =
    (a-b)(a+b), giving factors p = a-b and q = a+b.

    Args:
        n: The integer to factor (should be an odd composite).
        max_steps: Maximum number of iterations before giving up.

    Returns:
        A tuple (p, q) with p * q == n and 1 < p <= q < n, or None if no
        factorization was found within max_steps.

    Raises:
        ValueError: If n is even or n <= 1.
    """
    if n <= 1:
        raise ValueError(f"n must be > 1; got {n}")
    if n % 2 == 0:
        return 2, n // 2

    a = isqrt(n)
    if a * a == n:
        # n is a perfect square
        return a, a

    a += 1  # start just above sqrt(n)

    for _ in range(max_steps):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            p, q = a - b, a + b
            if p > 1 and q < n:
                return (p, q) if p <= q else (q, p)
        a += 1

    return None
