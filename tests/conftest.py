import os
import struct

import pytest
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from pycrp import Crp
from pycrp.constants import MAGIC, VERSION_LEGACY, SALT_SIZE, KEY_LEN, SCRYPT_N, SCRYPT_R, SCRYPT_P

PASSWORD = "unit-test-passphrase-do-not-reuse"


@pytest.fixture
def password():
    return PASSWORD


@pytest.fixture
def crp(password):
    return Crp(password)


@pytest.fixture
def make_file(tmp_path):
    """Writes `content` to `tmp_path/name` (creating subdirectories as needed) and returns its path."""

    def _make(name: str, content: bytes) -> str:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return str(path)

    return _make


@pytest.fixture
def legacy_v1_file(tmp_path, password):
    """
    Builds a .crp file in the old (task 1) whole-file Fernet format by hand,
    independently of the current encrypt_file implementation, so tests can
    check that decrypt_file still reads it without relying on the package
    ever having written one itself.
    """

    def _make(file_name: str, data: bytes) -> str:
        salt = os.urandom(SALT_SIZE)
        kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        fernet_key = urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

        name_bytes = file_name.encode('utf-8')
        payload = struct.pack('>H', len(name_bytes)) + name_bytes + data
        token = Fernet(fernet_key).encrypt(payload)

        blob = MAGIC + bytes([VERSION_LEGACY]) + salt + token
        path = tmp_path / 'legacy.crp'
        path.write_bytes(blob)
        return str(path)

    return _make
