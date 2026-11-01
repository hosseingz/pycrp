# Pycrp

Pycrp is a command-line tool and Python library for encrypting and decrypting files with a passphrase. It streams data through authenticated AES-256-GCM encryption in fixed-size chunks, so memory use stays bounded regardless of file size, and supports encrypting entire directory trees recursively.

## Features

- **Streaming, authenticated encryption.** Files are encrypted with AES-256-GCM in independently authenticated chunks. A file is never loaded into memory in full; a multi-gigabyte file takes roughly constant memory to process.
- **Tamper detection.** Each chunk is authenticated, including its position in the stream, so a modified, reordered, or truncated `.crp` file is rejected rather than silently producing corrupted output.
- **Password-based key derivation.** Keys are derived from the passphrase with scrypt (a memory-hard KDF) and a random salt generated per file, rather than from a bare hash of the passphrase.
- **Optional compression.** Data can be compressed with zlib before encryption, which also reduces the plaintext redundancy exposed to the cipher.
- **Recursive directory mode.** An entire directory tree can be encrypted or decrypted in one command, with the original folder structure preserved.
- **Secure passphrase entry.** The passphrase is read from a hidden terminal prompt, not a command-line argument, so it never ends up in shell history or process listings. It can also be supplied through an environment variable for scripted or CI use.
- **Optional secure deletion.** Source files can be overwritten and removed after a successful encryption with `--shred` (see the caveats below).
- **Backward-compatible decryption.** `.crp` files produced by earlier (pre-2.0) versions of this tool remain decryptable.

## Installation

```bash
pip install pycrp
```

## Usage

The tool provides two commands: `enc` to encrypt files and `dec` to decrypt them. Both operate on a directory of files at a time.

### Encrypting files

```bash
pycrp enc --dir <directory> --export <export_directory>
```

You will be prompted for a passphrase twice, to catch typing mistakes before they lock you out of your own files. Options:

- `-d, --dir <directory>`: Directory containing the files to encrypt. Defaults to the current directory.
- `-ex, --export <directory>`: Directory to write the encrypted `.crp` files into. Created automatically if it does not exist. Defaults to `crp-files/`.
- `-r, --recursive`: Also encrypt files in subdirectories, mirroring the folder structure under the export directory.
- `--shred`: Overwrite and permanently delete each source file once it has been encrypted. Prompts for confirmation unless `-y/--yes` is also given.
- `--shred-passes <n>`: Number of overwrite passes before deletion (default: 3). Has no effect without `--shred`.
- `-y, --yes`: Skip the `--shred` confirmation prompt.
- `-k, --key <passphrase>`: Supply the passphrase directly instead of being prompted. Only recommended for scripted use; see **Non-interactive use** below for a safer alternative.

Example:

```bash
pycrp enc --dir ./myfiles --export ./encrypted-files --recursive
```

### Decrypting files

```bash
pycrp dec --dir <directory> --export <export_directory>
```

You will be prompted for the passphrase once (no confirmation, since typing a wrong passphrase twice confirms nothing). Options mirror `enc`'s `-d`, `-ex`, `-r`, and `-k`; `--shred` and `--shred-passes` do not apply to decryption.

Example:

```bash
pycrp dec --dir ./encrypted-files --export ./decrypted-files --recursive
```

### Non-interactive use

For scripts or CI pipelines, set the `PYCRP_KEY` environment variable instead of using `-k` or the interactive prompt:

```bash
export PYCRP_KEY="my-passphrase"
pycrp enc --dir ./myfiles --export ./encrypted-files
```

An environment variable is generally a better fit for automation than a command-line argument: it does not appear in shell history, and most CI systems can mask variables flagged as secrets in their logs.

### Batch output

Both commands print a per-file status line as each file is processed, followed by a short summary once the batch finishes:

```
--- 3 file(s) processed ---
Decrypted: 1
Wrong key: 1
    other.crp
Corrupted or unsupported: 1
    broken.crp (Truncated chunk data.)
```

## Python API

```python
from pycrp import Crp

crp = Crp("my-passphrase")

# Encrypt a file
encrypted_path = crp.encrypt_file("path/to/file.txt", export_dir_path="encrypted_files")

# Decrypt it back
decrypted_path = crp.decrypt_file(encrypted_path, export_dir_path="decrypted_files")
```

`encrypt_file` and `decrypt_file` stream to and from disk directly; neither loads a whole file into memory. Relevant parameters:

- `encrypt_file(path, export_dir_path=None, file_name=None, chunk_size=1048576, compress=True, embedded_name=None, progress_callback=None)`
- `decrypt_file(path, export_dir_path=None, file_name=None, progress_callback=None)`

`embedded_name` stores a name (optionally a relative path, e.g. `"docs/notes.txt"`) inside the container, which `decrypt_file` uses to recreate the original location under its export directory; this is how recursive mode preserves directory structure. A name that would resolve outside the export directory is rejected.

Secure deletion is available as a standalone function:

```python
from pycrp import secure_delete

secure_delete("path/to/file.txt", passes=3)
```

### Exceptions

- `InvalidKey`: the passphrase is wrong, or the data has been tampered with.
- `CorruptedFile`: the `.crp` container is malformed, truncated, or its stored name would escape the export directory.
- `UnsupportedVersion`: the file was produced by an incompatible format version.
- `ShredError`: a file could not be overwritten or removed during secure deletion.

## File format

A `.crp` file stores a 4-byte magic value, a 1-byte format version, and then version-specific fields: a random salt for key derivation, a random nonce prefix, the chunk size used, a compression flag, and a sequence of length-prefixed, independently authenticated ciphertext chunks. Each chunk's authentication covers both its position in the file and whether it is the final chunk, so truncating or reordering the file is detected rather than silently accepted.

## On secure deletion (`--shred`)

Overwriting a file's bytes before deleting it is a real improvement over a plain delete, which only removes the file's directory entry and leaves its data on disk untouched. It is not, however, a guarantee on every kind of storage:

- On SSDs, wear-leveling means a logical overwrite is often written to different physical cells than the original data occupied; the original cells persist until the drive reclaims them on its own schedule.
- Copy-on-write filesystems (Btrfs, ZFS, APFS) never overwrite a block in place; a "changed" file is a new set of blocks, with the old ones reachable until a snapshot or the filesystem frees them.
- A file that has already been backed up, synced, or snapshotted has copies this tool has no way to find or affect.

If your threat model includes forensic recovery from SSD or copy-on-write storage, full-disk encryption is the more reliable tool. `--shred` is still worth using on top of that, and on conventional filesystems over spinning disks it is meaningfully more thorough than a plain delete.

## Compatibility

Files encrypted with versions of this tool prior to 2.0.0 (which encrypted a whole file at once with Fernet, without chunking) remain decryptable with the current version. New files are always written in the current streaming format.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The test suite includes integration tests, marked `integration`, that exercise larger files and tampered or truncated containers; run `pytest -m "not integration"` to skip them for a faster feedback loop during development.

## Contributing

Issues and pull requests are welcome.

## License

MIT License.
