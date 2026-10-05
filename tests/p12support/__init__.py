# coding: utf-8
"""
Test-only helpers for exercising the PKCS#12 inspection API.

These helpers implement just enough cryptography (PKCS#12 PBE with 3-key
triple DES and the PFX MAC) to build PFX files in memory and to act as the
caller-supplied password/decryption/MAC callbacks. The production
``asn1crypto.pkcs12`` module never imports this package and contains no
cryptographic code itself.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

from ._des import des_ecb, des_cbc_encrypt, des_cbc_decrypt
from ._pbe import (
    PKCS12Error,
    pkcs12_pbe_decrypt,
    pkcs12_pbe_encrypt,
    pfx_mac,
    verify_pfx_mac,
)
from ._builder import (
    build_pfx,
    make_cert,
    make_private_key,
    make_shrouded_key_bag,
    make_safe_bag,
    make_safe_contents,
)

__all__ = [
    'PKCS12Error',
    'build_pfx',
    'des_cbc_decrypt',
    'des_cbc_encrypt',
    'des_ecb',
    'make_cert',
    'make_private_key',
    'make_safe_bag',
    'make_safe_contents',
    'make_shrouded_key_bag',
    'pfx_mac',
    'pkcs12_pbe_decrypt',
    'pkcs12_pbe_encrypt',
    'verify_pfx_mac',
]
