"""
Pollard's Rho Factorization Algorithm.

A probabilistic algorithm for integer factorization with expected time
complexity O(n^(1/4)) and very small space requirements.  Effective for
finding small prime factors of large composites.

Reference: J. M. Pollard, "A Monte Carlo method for factorization", BIT, 1975.
"""

import math
from typing import Optional
from ..utils import gcd


def pollard_rho(n: int, max_steps: int = 1_000_000) -> Optional[int]:
    """
    Attempt to find a non-trivial factor of n using Pollard's rho algorithm.

    Uses Floyd's cycle detection with f(x) = (x^2 + 1) mod n.

    Args:
        n: The integer to factor (must be composite and > 1).
        max_steps: Maximum number of iterations before giving up.

    Returns:
        A non-trivial factor of n (1 < factor < n), or None if unsuccessful.
        Returns None if n is prime (per a quick primality pre-check).

    Raises:
        ValueError: If n <= 1.
    """
    if n <= 1:
        raise ValueError(f"n must be > 1; got {n}")
    if n % 2 == 0:
        return 2

    from ..utils import is_probable_prime
    if is_probable_prime(n):
        return None  # n is prime; no factor to find

    def f(x: int) -> int:
        return (x * x + 1) % n

    x = 2
    y = 2
    d = 1
    steps = 0

    while d == 1 and steps < max_steps:
        x = f(x)
        y = f(f(y))
        d = gcd(abs(x - y), n)
        steps += 1

    if 1 < d < n:
        return d

    # Brent's improvement: try a different starting point and constant c
    for c in range(1, 20):
        x = 2
        y = 2
        d = 1

        def fc(x: int) -> int:
            return (x * x + c) % n

        steps = 0
        while d == 1 and steps < max_steps:
            x = fc(x)
            y = fc(fc(y))
            d = gcd(abs(x - y), n)
            steps += 1

        if 1 < d < n:
            return d

    return None
