# -*- coding: utf-8 -*-
"""
Binary format constants for the .crp container.

Two format versions share the same magic bytes and are told apart by the
VERSION byte right after it:

VERSION 1 (legacy, whole-file):
    MAGIC(4="CRP1") + VERSION(1=1) + SALT(16) + FERNET_TOKEN(rest)
    The whole file is loaded into memory, encrypted as a single Fernet
    token. Kept only so old .crp files made by task 1 can still be
    decrypted; new files are never written in this format.

VERSION 2 (current, streaming/chunked):
    MAGIC(4="CRP1") + VERSION(1=2) + SALT(16) + NONCE_PREFIX(8) +
    CHUNK_SIZE(4, big-endian) + COMPRESSED(1, 0/1) +
    CHUNK* (until EOF)

    Each CHUNK is: LEN(4, big-endian) + CIPHERTEXT_WITH_TAG(LEN bytes),
    encrypted with AES-256-GCM using:
        nonce = NONCE_PREFIX (8 bytes) + chunk_index (4 bytes, big-endian)
        aad   = chunk_index (4 bytes, big-endian) + is_last (1 byte, bool)
    Including is_last in the authenticated associated data means an
    attacker cannot silently truncate the stream: dropping the real final
    chunk leaves a chunk whose stored AAD says is_last=False being
    presented at EOF, which fails authentication.

    The plaintext stream that gets chunked (and optionally zlib-compressed
    beforehand) is: FNAME_LEN(2, big-endian) + FNAME(utf-8) + FILE_DATA.
"""

MAGIC = b"CRP1"

VERSION_LEGACY = 1   # task 1 format: whole-file Fernet, kept for decrypting old files
VERSION_STREAM = 2   # task 2 format: chunked, streaming AEAD (current default)

SALT_SIZE = 16          # bytes, random salt per encryption operation
KEY_LEN = 32            # bytes, length of the raw derived key (AES-256 / Fernet secret)

# scrypt cost parameters (memory-hard KDF, no extra dependency required).
# N=2**14, r=8, p=1 is the "interactive" scrypt profile recommended by RFC 7914
# for cases where the derivation must happen fast enough for a CLI tool
# while still being expensive to brute force.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1

HEADER_SIZE_V1 = len(MAGIC) + 1 + SALT_SIZE

NONCE_SIZE = 12                           # AES-GCM standard nonce size
NONCE_PREFIX_SIZE = NONCE_SIZE - 4        # remaining 4 bytes are the per-chunk counter
CHUNK_LEN_FIELD_SIZE = 4                  # bytes used to store each chunk's ciphertext length
GCM_TAG_SIZE = 16

HEADER_SIZE_V2 = (
    len(MAGIC) + 1 + SALT_SIZE + NONCE_PREFIX_SIZE + 4 + 1
)  # ... + chunk_size(4) + compressed flag(1)

DEFAULT_CHUNK_SIZE = 1024 * 1024   # 1 MiB plaintext chunk before encryption
READ_BLOCK_SIZE = 64 * 1024        # 64 KiB blocks used to read the source file
MAX_CHUNK_INDEX = 2 ** 32 - 1      # counter is a 4-byte big-endian integer
