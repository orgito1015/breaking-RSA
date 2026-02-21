# breaking-RSA

A Python environment for researching, testing, and debugging RSA cryptography and its classical vulnerabilities.

## Features

- **Core RSA** — key generation, encryption, decryption, signing, and verification (textbook / raw RSA)
- **Attack modules** — ready-to-use implementations of well-known RSA weaknesses
  - Fermat's factorization (close primes)
  - Wiener's attack (small private exponent)
  - Common modulus attack (same `n`, different `e`)
  - Håstad's broadcast / small-exponent attack (same message, small `e`)
  - Pollard's rho factorization
- **Utilities** — Miller-Rabin primality test, modular arithmetic, integer roots, continued fractions
- **Test suite** — 61 pytest tests covering core functionality and all attack modules

## Project Layout

```
breaking-RSA/
├── rsa_research/
│   ├── __init__.py
│   ├── rsa_core.py          # RSA key gen, encrypt, decrypt, sign, verify
│   ├── utils.py             # Primality, modular arithmetic, integer roots, CF
│   └── attacks/
│       ├── __init__.py
│       ├── fermat.py        # Fermat's factorization (close primes)
│       ├── wiener.py        # Wiener's continued-fraction attack (small d)
│       ├── common_modulus.py # Common modulus attack
│       ├── small_exponent.py # Håstad broadcast / cube-root attack
│       └── pollard_rho.py   # Pollard's rho factorization
├── tests/
│   ├── test_rsa_core.py
│   ├── test_attacks.py
│   └── test_utils.py
├── requirements.txt
└── pyproject.toml
```

## Quick Start

### Install

```bash
# No external dependencies — only pytest for testing
pip install pytest
```

### Running Tests

```bash
PYTHONPATH=. python -m pytest tests/ -v
```

### Usage Examples

```python
from rsa_research import generate_keypair, encrypt, decrypt, sign, verify
from rsa_research import attacks

# --- Key generation ---
key = generate_keypair(bits=1024)   # standard key
pub = key.public_key                # public-only view

# --- Encryption / decryption ---
m = 12345
c = encrypt(m, key)
assert decrypt(c, key) == m

# --- Sign / verify ---
sig = sign(m, key)
assert verify(sig, key) == m

# --- Fermat's factorization (works when p ≈ q) ---
# Build a deliberately weak key with very close primes
from rsa_research.utils import generate_prime, modinv, gcd
p = generate_prime(64)
q = p + 2
from rsa_research.utils import is_probable_prime
while not is_probable_prime(q):
    q += 2
n = p * q
result = attacks.fermat_factor(n)
if result:
    print(f"Fermat found: {result[0]} × {result[1]}")

# --- Wiener's attack (works when d < n^0.25 / 3) ---
recovered_d = attacks.wiener_attack(key)   # returns None for a healthy key
print(f"Wiener recovered d: {recovered_d}")

# --- Common modulus attack ---
# Two keys sharing the same n but using different public exponents
c1 = encrypt(42, key)
# (create key2 with same n, different e — see tests/test_attacks.py for full example)

# --- Håstad broadcast attack (e=3, same message sent to 3 recipients) ---
e = 3
keys = [generate_keypair(bits=512, e=e) for _ in range(3)]
m_small = 99
ciphertexts = [(k.n, encrypt(m_small, k)) for k in keys]
recovered = attacks.small_exponent_attack(ciphertexts, e)
print(f"Hastad recovered: {recovered}")  # → 99

# --- Pollard's rho ---
factor = attacks.pollard_rho(n)
print(f"Pollard's rho found factor: {factor}")
```

## Attack Summary

| Attack | Condition | Module |
|---|---|---|
| **Fermat** | `p` and `q` are close (`|p-q|` small) | `attacks.fermat_factor` |
| **Wiener** | Private exponent `d < n^0.25 / 3` | `attacks.wiener_attack` |
| **Common modulus** | Same `n` used with two different `e` values | `attacks.common_modulus_attack` |
| **Small exponent (Håstad)** | Same `m` encrypted with small `e` to ≥ `e` recipients | `attacks.small_exponent_attack` |
| **Pollard's rho** | `n` has small prime factors | `attacks.pollard_rho` |

## Security Note

This repository is an **educational research tool**. The RSA implementation is *textbook RSA* (no padding). It should **not** be used in production systems. Always use a well-audited library (e.g., `cryptography`) with proper padding (OAEP/PSS) for real applications.
