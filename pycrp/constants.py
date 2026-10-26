# -*- coding: utf-8 -*-
"""
Binary format constants for the .crp container.

File layout:
    MAGIC   (4 bytes)   b"CRP1"
    VERSION (1 byte)    format version, currently 1
    SALT    (16 bytes)  random salt used to derive the Fernet key (scrypt)
    TOKEN   (rest)      a Fernet token. Fernet already embeds its own
                         IV/nonce, a version/timestamp, and an
                         HMAC-SHA256 authentication tag, so no separate
                         nonce/MAC fields are needed in this header.
"""

MAGIC = b"CRP1"
VERSION = 1

SALT_SIZE = 16          # bytes, random salt per encryption operation
KEY_LEN = 32            # bytes, length of the raw key fed into Fernet (pre base64)

# scrypt cost parameters (memory-hard KDF, no extra dependency required).
# N=2**14, r=8, p=1 is the "interactive" scrypt profile recommended by RFC 7914
# for cases where the derivation must happen fast enough for a CLI tool
# while still being expensive to brute force.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1

HEADER_SIZE = len(MAGIC) + 1 + SALT_SIZE
