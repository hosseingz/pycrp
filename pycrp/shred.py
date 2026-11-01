"""
Best-effort secure deletion of plaintext source files.

A plain `os.remove` only drops a file's directory entry; the data itself
stays on the physical medium until something else happens to reuse those
blocks, which can be a long time. Overwriting the content before removal
closes that gap for the common case: a conventional, in-place filesystem
on a spinning disk or a directly-addressed SSD.

It does not close it in every case, and callers relying on this for
regulatory or forensic purposes should know where it falls short:

- SSDs use wear-leveling, so a logical overwrite is frequently written to
  different physical cells than the original data occupied. The old
  cells, and the data in them, persist until the drive's own garbage
  collector reclaims them, on its own schedule.
- Copy-on-write filesystems (Btrfs, ZFS, APFS) never overwrite a block in
  place by design; a "changed" file is really a new set of blocks, with
  the old ones reachable until a snapshot or the filesystem itself frees
  them.
- Anything that copied the file first (a backup job, a filesystem
  snapshot, a cloud sync client) still has an untouched copy that this
  module knows nothing about.

None of this makes the overwrite pointless: on the storage this module
can actually affect, it is a real improvement over a plain delete. It is
not, by itself, a substitute for full-disk encryption when the threat
model includes forensic recovery from SSD or CoW-filesystem storage.
"""

import os
import secrets

from .constants import DEFAULT_SHRED_PASSES, READ_BLOCK_SIZE
from .exceptions import ShredError


def overwrite_file(path: str, passes: int = DEFAULT_SHRED_PASSES, chunk_size: int = READ_BLOCK_SIZE) -> None:
    """
    Overwrites a file's existing content in place, `passes` times, without
    removing it. Pair this with `secure_delete` to also remove the file
    afterwards; this function exists on its own mainly so it can be tested
    without also exercising the delete.

    All but the last pass write cryptographically random bytes; the last
    pass (when there is more than one) writes zeros, following the
    traditional random/.../zero shred pattern. Each pass is flushed and
    fsync'd before the next begins, so the writes are not left sitting in
    an OS buffer; see the module docstring for what that can and can't
    guarantee on the underlying storage.

    Args:
        path (str): Path of the file to overwrite.
        passes (int, optional): Number of overwrite passes. Defaults to
            DEFAULT_SHRED_PASSES.
        chunk_size (int, optional): Size of each write, in bytes.

    Raises:
        ValueError: If `path` is empty or `passes` is not positive.
        FileNotFoundError: If `path` does not exist or is not a regular file.
    """
    if not path:
        raise ValueError('Path cannot be empty.')

    if passes <= 0:
        raise ValueError('passes must be a positive integer.')

    if not os.path.isfile(path):
        raise FileNotFoundError(f'{path} does not exist or is not a regular file.')

    size = os.path.getsize(path)

    with open(path, 'r+b') as file:
        for pass_index in range(passes):
            is_final_zero_pass = passes > 1 and pass_index == passes - 1

            file.seek(0)
            remaining = size
            while remaining > 0:
                block_len = min(chunk_size, remaining)
                block = bytes(block_len) if is_final_zero_pass else os.urandom(block_len)
                file.write(block)
                remaining -= block_len

            file.flush()
            os.fsync(file.fileno())


def secure_delete(path: str, passes: int = DEFAULT_SHRED_PASSES, chunk_size: int = READ_BLOCK_SIZE) -> None:
    """
    Overwrites a file (see `overwrite_file`), renames it to a random name
    so its original name doesn't linger in directory metadata or a
    filesystem journal, and removes it.

    Args:
        path (str): Path of the file to destroy.
        passes (int, optional): Number of overwrite passes. Defaults to
            DEFAULT_SHRED_PASSES.
        chunk_size (int, optional): Size of each write, in bytes.

    Raises:
        ValueError: If `path` is empty or `passes` is not positive.
        FileNotFoundError: If `path` does not exist or is not a regular file.
        ShredError: If the file could not be overwritten, renamed, or
            removed. The underlying OSError is attached as `__cause__`.
    """
    try:
        overwrite_file(path, passes=passes, chunk_size=chunk_size)

        directory = os.path.dirname(os.path.abspath(path)) or '.'
        obscured_path = os.path.join(directory, f'.{secrets.token_hex(8)}.tmp')

        try:
            os.replace(path, obscured_path)
        except OSError:
            # Renaming first is a bonus (it keeps the original name out of
            # the directory listing and, on some filesystems, the journal),
            # not a requirement; fall back to removing the original path.
            obscured_path = path

        os.remove(obscured_path)

    except (ValueError, FileNotFoundError):
        raise
    except OSError as error:
        raise ShredError(f'Could not securely delete {path}: {error}') from error
