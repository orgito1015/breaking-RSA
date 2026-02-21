"""
Wiener's Attack on RSA.

When the private exponent d is small (d < n^0.25 / 3), Wiener's attack can
recover d from the public key (n, e) using the theory of continued fractions.

Reference: M. J. Wiener, "Cryptanalysis of short RSA secret exponents",
IEEE Transactions on Information Theory, 1990.
"""

from typing import Optional
from ..utils import convergents, isqrt
from ..rsa_core import RSAKey


def wiener_attack(key: RSAKey) -> Optional[int]:
    """
    Attempt Wiener's continued-fraction attack to recover the private exponent d.

    Args:
        key: An RSAKey with public components (n, e).

    Returns:
        The private exponent d if the attack succeeds, or None otherwise.

    The attack works when d < n^0.25 / 3.  For well-generated keys (d large)
    it will return None.
    """
    n, e = key.n, key.e

    for k, d in convergents(e, n):
        if k == 0:
            continue

        # Check if phi = (e*d - 1) / k is an integer
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # Verify phi is consistent: n - phi + 1 should equal p + q,
        # and p, q should be real roots of x^2 - (p+q)x + n = 0.
        # p + q = n - phi + 1,  p * q = n
        s = n - phi + 1          # p + q
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue

        sqrt_disc = isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue

        # Both roots must be positive integers
        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2
        if p * q == n and p > 1 and q > 1:
            return d

    return None
