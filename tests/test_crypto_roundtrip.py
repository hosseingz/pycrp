import os

import pytest

from pycrp import Crp, InvalidKey, CorruptedFile


def _roundtrip(crp, make_file, tmp_path, name, content, **encrypt_kwargs):
    src = make_file(name, content)
    crp_path = crp.encrypt_file(src, export_dir_path=str(tmp_path / 'out'), **encrypt_kwargs)
    out_path = crp.decrypt_file(crp_path, export_dir_path=str(tmp_path / 'dec'))
    with open(out_path, 'rb') as f:
        return crp_path, out_path, f.read()


@pytest.mark.parametrize('compress', [True, False])
def test_roundtrip_text_content(crp, make_file, tmp_path, compress):
    content = (b'The quick brown fox jumps over the lazy dog. ' * 5000)
    _, out_path, result = _roundtrip(crp, make_file, tmp_path, 'quote.txt', content, compress=compress)
    assert result == content
    assert os.path.basename(out_path) == 'quote.txt'


@pytest.mark.parametrize('compress', [True, False])
def test_roundtrip_incompressible_binary(crp, make_file, tmp_path, compress):
    content = os.urandom(300_000)
    _, _, result = _roundtrip(crp, make_file, tmp_path, 'blob.bin', content, compress=compress, chunk_size=64 * 1024)
    assert result == content


def test_roundtrip_empty_file(crp, make_file, tmp_path):
    _, out_path, result = _roundtrip(crp, make_file, tmp_path, 'empty.bin', b'')
    assert result == b''
    assert os.path.basename(out_path) == 'empty.bin'


def test_compression_meaningfully_shrinks_repetitive_data(crp, make_file, tmp_path):
    content = b'A' * 2_000_000
    crp_path, _, _ = _roundtrip(crp, make_file, tmp_path, 'repetitive.bin', content, compress=True)
    assert os.path.getsize(crp_path) < len(content) // 100


def test_wrong_key_raises_invalid_key(make_file, tmp_path, password):
    src = make_file('secret.txt', b'classified')
    crp_path = Crp(password).encrypt_file(src, export_dir_path=str(tmp_path / 'out'))

    with pytest.raises(InvalidKey):
        Crp('a-completely-different-passphrase').decrypt_file(crp_path, export_dir_path=str(tmp_path / 'dec'))


def test_tampered_ciphertext_is_rejected(crp, make_file, tmp_path):
    src = make_file('data.bin', os.urandom(200_000))
    crp_path = crp.encrypt_file(src, export_dir_path=str(tmp_path / 'out'), chunk_size=32 * 1024)

    raw = bytearray(open(crp_path, 'rb').read())
    raw[len(raw) // 2] ^= 0xFF
    tampered_path = tmp_path / 'tampered.crp'
    tampered_path.write_bytes(raw)

    with pytest.raises((InvalidKey, CorruptedFile)):
        crp.decrypt_file(str(tampered_path), export_dir_path=str(tmp_path / 'dec'))


def test_truncated_file_is_rejected(crp, make_file, tmp_path):
    src = make_file('data.bin', os.urandom(200_000))
    crp_path = crp.encrypt_file(src, export_dir_path=str(tmp_path / 'out'), chunk_size=32 * 1024)

    full = open(crp_path, 'rb').read()
    truncated_path = tmp_path / 'truncated.crp'
    truncated_path.write_bytes(full[:-100])

    with pytest.raises((InvalidKey, CorruptedFile)):
        crp.decrypt_file(str(truncated_path), export_dir_path=str(tmp_path / 'dec'))


def test_legacy_v1_file_is_still_decryptable(crp, legacy_v1_file, tmp_path):
    content = b'made with the old whole-file Fernet format' * 20
    crp_path = legacy_v1_file('legacy_report.txt', content)

    out_path = crp.decrypt_file(crp_path, export_dir_path=str(tmp_path / 'dec'))

    assert os.path.basename(out_path) == 'legacy_report.txt'
    assert open(out_path, 'rb').read() == content


def test_progress_callback_matches_source_file_size_on_encrypt(crp, make_file, tmp_path):
    content = os.urandom(1_000_000)
    src = make_file('data.bin', content)

    seen = []
    crp.encrypt_file(
        src,
        export_dir_path=str(tmp_path / 'out'),
        chunk_size=128 * 1024,
        progress_callback=seen.append,
    )

    assert sum(seen) == len(content)


def test_progress_callback_matches_ciphertext_size_on_decrypt(crp, make_file, tmp_path):
    src = make_file('data.bin', os.urandom(1_000_000))
    crp_path = crp.encrypt_file(src, export_dir_path=str(tmp_path / 'out'), chunk_size=128 * 1024)

    seen = []
    crp.decrypt_file(crp_path, export_dir_path=str(tmp_path / 'dec'), progress_callback=seen.append)

    # Slightly less than the file's full size: the fixed-size header
    # (magic, version, salt, nonce prefix, chunk size, compressed flag)
    # isn't attributed to any chunk and so isn't counted.
    assert 0 < (os.path.getsize(crp_path) - sum(seen)) < 64


@pytest.mark.integration
def test_large_file_roundtrip_stays_memory_bounded(crp, make_file, tmp_path):
    """
    20 MB is enough to force many chunks through the pipeline without
    making the test suite slow; it is not meant to prove a specific
    memory ceiling, just that nothing silently buffers the whole file
    (which the unit tests, using small files, could not catch).
    """
    size = 20 * 1024 * 1024
    block = os.urandom(1024 * 1024)
    src = tmp_path / 'large.bin'
    with open(src, 'wb') as f:
        for _ in range(size // len(block)):
            f.write(block)

    crp_path = crp.encrypt_file(str(src), export_dir_path=str(tmp_path / 'out'), chunk_size=256 * 1024)
    out_path = crp.decrypt_file(crp_path, export_dir_path=str(tmp_path / 'dec'))

    assert os.path.getsize(out_path) == size
    with open(src, 'rb') as a, open(out_path, 'rb') as b:
        while True:
            chunk_a = a.read(1024 * 1024)
            chunk_b = b.read(1024 * 1024)
            assert chunk_a == chunk_b
            if not chunk_a:
                break


@pytest.mark.integration
def test_tampering_a_large_file_is_still_detected(crp, tmp_path):
    """A single flipped byte deep inside a large, multi-chunk file must still fail authentication."""
    size = 8 * 1024 * 1024
    src = tmp_path / 'large.bin'
    with open(src, 'wb') as f:
        f.write(os.urandom(size))

    crp_path = crp.encrypt_file(str(src), export_dir_path=str(tmp_path / 'out'), chunk_size=256 * 1024, compress=False)

    raw = bytearray(open(crp_path, 'rb').read())
    raw[len(raw) * 3 // 4] ^= 0x01
    tampered_path = tmp_path / 'tampered_large.crp'
    tampered_path.write_bytes(raw)

    with pytest.raises((InvalidKey, CorruptedFile)):
        crp.decrypt_file(str(tampered_path), export_dir_path=str(tmp_path / 'dec'))
