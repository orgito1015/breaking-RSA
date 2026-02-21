"""
Common Modulus Attack on RSA.

If two ciphertexts are created by encrypting the *same* plaintext m with the
*same* modulus n but *different* public exponents e1 and e2, and
gcd(e1, e2) == 1, an attacker can recover m without knowing either private key.

This scenario arises when the same n is reused with multiple public exponents
(a well-known deployment mistake).
"""

from typing import Optional
from ..utils import extended_gcd, gcd


def common_modulus_attack(
    n: int,
    e1: int,
    e2: int,
    c1: int,
    c2: int,
) -> Optional[int]:
    """
    Recover the plaintext m from two RSA ciphertexts encrypted under the same
    modulus n but different public exponents e1 and e2, where gcd(e1, e2) == 1.

    The recovery uses Bezout's identity: find integers a, b such that
    a*e1 + b*e2 == 1 (via extended GCD).  Then:
        m ≡ c1^a * c2^b  (mod n)

    Args:
        n:  Shared RSA modulus.
        e1: First public exponent.
        e2: Second public exponent.
        c1: Ciphertext encrypted with e1: c1 = m^e1 mod n.
        c2: Ciphertext encrypted with e2: c2 = m^e2 mod n.

    Returns:
        Recovered plaintext integer m, or None if gcd(e1, e2) != 1.
    """
    if gcd(e1, e2) != 1:
        return None

    _, a, b = extended_gcd(e1, e2)
    # a*e1 + b*e2 == 1
    # m ≡ c1^a * c2^b (mod n)

    if a < 0:
        c1_term = pow(modinv_int(c1, n), -a, n)
    else:
        c1_term = pow(c1, a, n)

    if b < 0:
        c2_term = pow(modinv_int(c2, n), -b, n)
    else:
        c2_term = pow(c2, b, n)

    return (c1_term * c2_term) % n


# ---------------------------------------------------------------------------
# Internal helper (avoids circular import with utils)
# ---------------------------------------------------------------------------

def modinv_int(a: int, m: int) -> int:
    """Modular inverse of a mod m (internal helper)."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {g}")
    return x % m
