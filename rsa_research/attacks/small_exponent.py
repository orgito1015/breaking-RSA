"""
Small Public Exponent Attack (Håstad's Broadcast Attack / Cube-Root Attack).

If the same message m is sent to k recipients using the *same* small public
exponent e (e.g. e=3) with *different* moduli n_1, ..., n_k, and
gcd(n_i, n_j) == 1 for all i != j, then by the Chinese Remainder Theorem (CRT)
we can recover m^e and take the integer e-th root to get m — without factoring
any modulus.

Special case (single ciphertext, small e):
    When m^e < n (message is small relative to n) the ciphertext c = m^e is an
    exact integer power and we can recover m by simply computing the e-th root
    of c over the integers.
"""

from typing import List, Optional, Tuple
from ..utils import integer_nth_root, gcd


def small_exponent_attack(
    ciphertexts: List[Tuple[int, int]],
    e: int,
) -> Optional[int]:
    """
    Recover plaintext m using Håstad's broadcast attack (CRT + integer root).

    Args:
        ciphertexts: List of (n_i, c_i) pairs — each ciphertext c_i = m^e mod n_i.
                     Must contain at least *e* entries with pairwise coprime moduli.
        e: The common small public exponent used for all encryptions.

    Returns:
        Recovered plaintext integer m, or None if the attack fails.

    Raises:
        ValueError: If fewer than e ciphertexts are provided, or moduli are not
                    pairwise coprime.
    """
    if len(ciphertexts) < e:
        raise ValueError(
            f"Need at least {e} ciphertexts for e={e}; got {len(ciphertexts)}"
        )

    # Verify pairwise coprimality
    for i in range(e):
        for j in range(i + 1, e):
            if gcd(ciphertexts[i][0], ciphertexts[j][0]) != 1:
                raise ValueError(
                    f"Moduli n_{i} and n_{j} are not coprime"
                )

    # Use the first e ciphertexts
    ns = [ct[0] for ct in ciphertexts[:e]]
    cs = [ct[1] for ct in ciphertexts[:e]]

    # CRT: find x ≡ c_i (mod n_i) for each i — this gives us m^e mod (n_1*...*n_e)
    x = _crt(cs, ns)

    # Take the integer e-th root of x to recover m
    m, exact = integer_nth_root(x, e)
    return m if exact else None


def _crt(remainders: List[int], moduli: List[int]) -> int:
    """Chinese Remainder Theorem: find x such that x ≡ r_i (mod m_i)."""
    from ..utils import modinv
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        x += r * Mi * modinv(Mi, m)
    return x % M
