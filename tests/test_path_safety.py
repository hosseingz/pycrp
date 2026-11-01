import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pycrp import CorruptedFile
from pycrp.main import _safe_join, _derive_key
from pycrp.constants import MAGIC, VERSION_STREAM, SALT_SIZE, NONCE_PREFIX_SIZE, DEFAULT_CHUNK_SIZE


def test_safe_join_accepts_nested_relative_path(tmp_path):
    result = _safe_join(str(tmp_path), 'docs/sub/file.txt')
    assert result == os.path.join(str(tmp_path), 'docs', 'sub', 'file.txt')


@pytest.mark.parametrize('malicious_name', [
    '../escape.txt',
    '../../escape.txt',
    'docs/../../escape.txt',
    '/etc/passwd',
    '',
])
def test_safe_join_rejects_unsafe_names(tmp_path, malicious_name):
    with pytest.raises(CorruptedFile):
        _safe_join(str(tmp_path), malicious_name)


def _build_malicious_crp(tmp_path, password, embedded_name, payload_data=b'pwned'):
    """Hand-crafts a syntactically valid v2 .crp whose embedded name is an attack string."""
    salt = os.urandom(SALT_SIZE)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    key = _derive_key(password, salt)
    aead = AESGCM(key)

    name_bytes = embedded_name.encode('utf-8')
    metadata = struct.pack('>H', len(name_bytes)) + name_bytes + payload_data

    nonce = nonce_prefix + struct.pack('>I', 0)
    aad = struct.pack('>I?', 0, True)
    ciphertext = aead.encrypt(nonce, metadata, aad)

    path = tmp_path / 'malicious.crp'
    with open(path, 'wb') as f:
        f.write(MAGIC)
        f.write(bytes([VERSION_STREAM]))
        f.write(salt)
        f.write(nonce_prefix)
        f.write(struct.pack('>I', DEFAULT_CHUNK_SIZE))
        f.write(bytes([0]))
        f.write(struct.pack('>I', len(ciphertext)))
        f.write(ciphertext)

    return str(path)


def test_decrypt_file_blocks_path_traversal_in_embedded_name(crp, password, tmp_path):
    outside_target = tmp_path / 'outside_the_export_dir.txt'
    export_dir = tmp_path / 'export'
    export_dir.mkdir()

    evil_name = '../outside_the_export_dir.txt'
    malicious_path = _build_malicious_crp(tmp_path, password, evil_name)

    with pytest.raises(CorruptedFile):
        crp.decrypt_file(malicious_path, export_dir_path=str(export_dir))

    assert not outside_target.exists()


def test_decrypt_file_recreates_directory_tree_from_embedded_name(crp, make_file, tmp_path):
    src = make_file('notes.txt', b'nested content')
    crp_path = crp.encrypt_file(
        src,
        export_dir_path=str(tmp_path / 'out'),
        embedded_name='docs/project/notes.txt',
    )

    out_path = crp.decrypt_file(crp_path, export_dir_path=str(tmp_path / 'dec'))

    expected = tmp_path / 'dec' / 'docs' / 'project' / 'notes.txt'
    assert out_path == str(expected)
    assert expected.read_bytes() == b'nested content'


def test_explicit_file_name_override_is_also_safety_checked(crp, make_file, tmp_path):
    src = make_file('notes.txt', b'content')
    crp_path = crp.encrypt_file(src, export_dir_path=str(tmp_path / 'out'))

    with pytest.raises(CorruptedFile):
        crp.decrypt_file(crp_path, export_dir_path=str(tmp_path / 'dec'), file_name='../escape.txt')
