import os

import pytest

from pycrp.shred import overwrite_file, secure_delete
from pycrp.exceptions import ShredError


def test_overwrite_file_keeps_size_and_changes_content(tmp_path):
    original = b'TOP SECRET' * 10_000
    path = tmp_path / 'secret.txt'
    path.write_bytes(original)

    overwrite_file(str(path), passes=3)

    assert path.exists()
    assert path.stat().st_size == len(original)
    assert path.read_bytes() != original


def test_overwrite_file_multi_pass_ends_on_zeros(tmp_path):
    original = b'TOP SECRET' * 10_000
    path = tmp_path / 'secret.txt'
    path.write_bytes(original)

    overwrite_file(str(path), passes=3)

    assert path.read_bytes() == bytes(len(original))


def test_overwrite_file_single_pass_is_random_not_forced_to_zero(tmp_path):
    original = b'TOP SECRET' * 10_000
    path = tmp_path / 'secret.txt'
    path.write_bytes(original)

    overwrite_file(str(path), passes=1)

    content = path.read_bytes()
    assert content != original
    assert content != bytes(len(original))


def test_overwrite_file_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        overwrite_file(str(tmp_path / 'does-not-exist.bin'))


@pytest.mark.parametrize('passes', [0, -1])
def test_overwrite_file_rejects_non_positive_passes(tmp_path, passes):
    path = tmp_path / 'f.bin'
    path.write_bytes(b'x')
    with pytest.raises(ValueError):
        overwrite_file(str(path), passes=passes)


def test_overwrite_file_handles_empty_file(tmp_path):
    path = tmp_path / 'empty.bin'
    path.write_bytes(b'')
    overwrite_file(str(path), passes=2)
    assert path.exists()
    assert path.stat().st_size == 0


def test_secure_delete_removes_the_file(tmp_path):
    path = tmp_path / 'secret.txt'
    path.write_bytes(b'gone soon')

    secure_delete(str(path))

    assert not path.exists()


def test_secure_delete_does_not_leave_the_obscuring_temp_file_behind(tmp_path):
    path = tmp_path / 'secret.txt'
    path.write_bytes(b'gone soon')

    secure_delete(str(path))

    assert list(tmp_path.iterdir()) == []


def test_secure_delete_wraps_unexpected_oserror(tmp_path, monkeypatch):
    path = tmp_path / 'secret.txt'
    path.write_bytes(b'data')

    def failing_remove(_path):
        raise OSError('simulated disk failure')

    monkeypatch.setattr('pycrp.shred.os.remove', failing_remove)

    with pytest.raises(ShredError) as excinfo:
        secure_delete(str(path))

    assert isinstance(excinfo.value.__cause__, OSError)


def test_secure_delete_propagates_missing_file_as_is(tmp_path):
    with pytest.raises(FileNotFoundError):
        secure_delete(str(tmp_path / 'does-not-exist.bin'))
