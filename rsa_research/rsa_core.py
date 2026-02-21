"""
Core RSA implementation: key generation, encryption, and decryption.
"""

import random
from dataclasses import dataclass
from typing import Optional, Tuple

from .utils import (
    generate_prime,
    modinv,
    is_probable_prime,
    gcd,
)


@dataclass
class RSAKey:
    """Holds an RSA public/private key pair (or just the public portion)."""

    n: int  # modulus
    e: int  # public exponent
    d: Optional[int] = None  # private exponent (None for public-only key)
    p: Optional[int] = None  # prime factor p
    q: Optional[int] = None  # prime factor q

    @property
    def bit_length(self) -> int:
        return self.n.bit_length()

    @property
    def public_key(self) -> "RSAKey":
        """Return a public-only copy of this key."""
        return RSAKey(n=self.n, e=self.e)

    def __repr__(self) -> str:
        has_private = self.d is not None
        return (
            f"RSAKey(bits={self.bit_length}, e={self.e}, "
            f"has_private={has_private})"
        )


def generate_keypair(
    bits: int = 1024,
    e: int = 65537,
    ensure_distinct_primes: bool = True,
) -> RSAKey:
    """
    Generate an RSA key pair.

    Args:
        bits: Total bit-length of the modulus n (each prime is bits//2 bits).
        e: Public exponent. Defaults to 65537 (F4).
        ensure_distinct_primes: If True, re-sample until p != q.

    Returns:
        An RSAKey with both public and private components.

    Raises:
        ValueError: If e is not valid (e.g. gcd(e, phi) != 1).
    """
    if bits < 16:
        raise ValueError("bits must be at least 16")
    if e < 3 or e % 2 == 0:
        raise ValueError("e must be an odd integer >= 3")

    half = bits // 2

    while True:
        p = generate_prime(half)
        q = generate_prime(half)

        if ensure_distinct_primes and p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) != 1:
            continue

        d = modinv(e, phi)
        return RSAKey(n=n, e=e, d=d, p=p, q=q)


def encrypt(message: int, key: RSAKey) -> int:
    """
    RSA encryption (textbook / raw RSA).

    Args:
        message: Integer plaintext. Must satisfy 0 <= message < key.n.
        key: An RSAKey (only n and e are required).

    Returns:
        Integer ciphertext c = message^e mod n.

    Raises:
        ValueError: If message is out of range.
    """
    if not (0 <= message < key.n):
        raise ValueError(f"message must be in [0, n-1]; got {message}")
    return pow(message, key.e, key.n)


def decrypt(ciphertext: int, key: RSAKey) -> int:
    """
    RSA decryption (textbook / raw RSA).

    Args:
        ciphertext: Integer ciphertext. Must satisfy 0 <= ciphertext < key.n.
        key: An RSAKey with the private exponent d.

    Returns:
        Integer plaintext m = ciphertext^d mod n.

    Raises:
        ValueError: If ciphertext is out of range or key has no private component.
    """
    if key.d is None:
        raise ValueError("key does not contain a private exponent (d)")
    if not (0 <= ciphertext < key.n):
        raise ValueError(f"ciphertext must be in [0, n-1]; got {ciphertext}")
    return pow(ciphertext, key.d, key.n)


def sign(message: int, key: RSAKey) -> int:
    """
    RSA signing (textbook): computes signature = message^d mod n.

    Args:
        message: Integer message hash. Must satisfy 0 <= message < key.n.
        key: An RSAKey with the private exponent d.

    Returns:
        Integer signature.
    """
    if key.d is None:
        raise ValueError("key does not contain a private exponent (d)")
    if not (0 <= message < key.n):
        raise ValueError(f"message must be in [0, n-1]; got {message}")
    return pow(message, key.d, key.n)


def verify(signature: int, key: RSAKey) -> int:
    """
    RSA signature verification (textbook): recovers message = signature^e mod n.

    Args:
        signature: Integer signature.
        key: An RSAKey (only n and e are required).

    Returns:
        Recovered integer message.
    """
    if not (0 <= signature < key.n):
        raise ValueError(f"signature must be in [0, n-1]; got {signature}")
    return pow(signature, key.e, key.n)
