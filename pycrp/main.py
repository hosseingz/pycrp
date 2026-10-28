from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from base64 import urlsafe_b64encode

from .exceptions import InvalidKey, CorruptedFile, UnsupportedVersion
from .constants import (
    MAGIC, VERSION_LEGACY, VERSION_STREAM,
    SALT_SIZE, KEY_LEN, SCRYPT_N, SCRYPT_R, SCRYPT_P,
    HEADER_SIZE_V1, HEADER_SIZE_V2,
    NONCE_PREFIX_SIZE, CHUNK_LEN_FIELD_SIZE,
    DEFAULT_CHUNK_SIZE, READ_BLOCK_SIZE, MAX_CHUNK_INDEX,
)

from pathlib import PurePosixPath
import os
import struct
import zlib


def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a raw KEY_LEN-byte key from a password and a salt using scrypt,
    a memory-hard KDF. Used directly as the AES-256-GCM key for the current
    streaming format.
    """
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode('utf-8'))


def _pack_metadata(stored_name: str) -> bytes:
    name_bytes = stored_name.replace(os.sep, '/').encode('utf-8')
    if len(name_bytes) > 0xFFFF:
        raise ValueError('File name is too long to be stored.')
    return struct.pack('>H', len(name_bytes)) + name_bytes


def _safe_join(base_dir: str, stored_name: str) -> str:
    """
    Resolves the name embedded in a .crp container against `base_dir`,
    rejecting anything that would land outside it.

    Stored names are always posix-style (forward slashes), including for
    files encrypted on Windows, so a directory tree round-trips the same
    way regardless of platform. A name is rejected if it is empty, is
    absolute, or contains a '..' segment; the resolved path is then
    checked against `base_dir` a second time with realpath, which also
    catches a '..' hidden behind a symlink.
    """
    if not stored_name:
        raise CorruptedFile('Stored file name is empty.')

    parts = PurePosixPath(stored_name).parts
    if not parts or any(part in ('..', '.', '') for part in parts) or PurePosixPath(stored_name).is_absolute():
        raise CorruptedFile(f'Stored file name is not a safe relative path: {stored_name!r}')

    candidate = os.path.join(base_dir, *parts)

    base_real = os.path.realpath(base_dir)
    candidate_real = os.path.realpath(candidate)
    if os.path.commonpath([base_real, candidate_real]) != base_real:
        raise CorruptedFile(f'Stored file name escapes the export directory: {stored_name!r}')

    return candidate


class _ChunkedByteReader:
    """
    Wraps an iterable of bytes (of any size) and re-chunks it into
    fixed-size pieces of at most `chunk_size` bytes, each tagged with
    whether it is the final piece. Memory use is bounded by chunk_size
    regardless of how much data the source iterable eventually produces.
    """

    def __init__(self, source, chunk_size: int):
        self._source = iter(source)
        self._chunk_size = chunk_size
        self._buf = bytearray()
        self._done = False

    def __iter__(self):
        return self

    def __next__(self):
        while len(self._buf) < self._chunk_size and not self._done:
            try:
                self._buf.extend(next(self._source))
            except StopIteration:
                self._done = True

        if not self._buf and self._done:
            raise StopIteration

        take = min(self._chunk_size, len(self._buf))
        chunk = bytes(self._buf[:take])
        del self._buf[:take]
        is_last = self._done and not self._buf
        return chunk, is_last


def _raw_source(path: str, metadata: bytes, read_block: int = READ_BLOCK_SIZE):
    """Yields metadata first, then the source file's content in fixed-size blocks."""
    yield metadata
    with open(path, 'rb') as file:
        while True:
            block = file.read(read_block)
            if not block:
                break
            yield block


def _compressed_source(path: str, metadata: bytes, read_block: int = READ_BLOCK_SIZE):
    """Like `_raw_source`, but streamed through a zlib compressor as it is read."""
    compressor = zlib.compressobj()
    for block in _raw_source(path, metadata, read_block):
        data = compressor.compress(block)
        if data:
            yield data
    tail = compressor.flush()
    if tail:
        yield tail


class Crp:
    """
    Encrypts/decrypts files with AES-256-GCM in fixed-size, independently
    authenticated chunks, so memory use stays bounded (roughly one chunk)
    regardless of file size, instead of loading the whole file into RAM.

    An optional zlib compression pass runs on the plaintext stream, before
    chunking and encryption, to shrink the ciphertext and reduce plaintext
    redundancy.

    See constants.py for the exact on-disk layout of both the legacy
    (task 1, whole-file Fernet) and current (task 2, streaming) formats.
    `decrypt_file` transparently supports both; `encrypt_file` only ever
    writes the current streaming format.

    Each container stores one name alongside the data, normally just the
    source file's base name. Callers that walk a directory tree can pass a
    relative path as `embedded_name` instead, so `decrypt_file` recreates
    the original subdirectories under its export directory.
    """

    def __init__(self, key: str):
        """
        Initializes the Crp object with a given encryption key (password).

        Args:
            key (str): A string that serves as the encryption password.

        Raises:
            ValueError: If the provided key is empty.
        """
        if not key:
            raise ValueError("An empty key is not Valid input.")

        self.__key = key

    # Encryption (streaming, v2)

    def encrypt_file(
        self,
        path: str,
        export_dir_path: str = None,
        file_name: str = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        compress: bool = True,
        embedded_name: str = None,
    ) -> str:
        """
        Streams, (optionally) compresses, and encrypts a file into a .crp
        container without loading the whole file into memory.

        Args:
            path (str): Path of the file to encrypt.
            export_dir_path (str, optional): Directory to write the .crp file
                into. Defaults to 'crp-files/'.
            file_name (str, optional): Name to give the .crp file on disk.
                Defaults to the source file's base name with a .crp extension.
            chunk_size (int, optional): Target plaintext chunk size, in bytes,
                before each chunk is encrypted. Defaults to 1 MiB.
            compress (bool, optional): Whether to zlib-compress the data
                before encrypting it. Defaults to True.
            embedded_name (str, optional): The name (or relative path, for
                recreating a directory tree on decrypt) stored inside the
                container and restored by `decrypt_file`. Defaults to the
                source file's base name. Callers that mirror a directory
                tree pass a relative path here, e.g. "docs/notes.txt";
                `file_name` and the on-disk layout are unaffected by this.

        Returns:
            str: The path of the written .crp file.

        Raises:
            ValueError: If the path is empty, the file does not exist, or
                chunk_size is not a positive integer.
        """

        if not path:
            raise ValueError("File path cannot be empty.")

        if os.path.exists(path) and not os.path.isfile(path):
            raise FileNotFoundError('The file does not exist.')

        if chunk_size <= 0:
            raise ValueError('chunk_size must be a positive integer.')

        source_name = os.path.basename(path)
        stored_name = embedded_name or source_name

        if file_name:
            base_name, current_ext = os.path.splitext(file_name)
            if current_ext != '.crp':
                file_name = f'{base_name}.crp'
        else:
            file_name = f"{os.path.splitext(source_name)[0]}.crp"

        export_dir_path = self.__ensure_dir_exists(export_dir_path or 'crp-files/')
        out_path = os.path.join(export_dir_path, file_name)

        salt = os.urandom(SALT_SIZE)
        nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
        key = _derive_key(self.__key, salt)
        aead = AESGCM(key)

        metadata = _pack_metadata(stored_name)
        source = _compressed_source(path, metadata) if compress else _raw_source(path, metadata)

        with open(out_path, 'wb') as out:
            out.write(MAGIC)
            out.write(bytes([VERSION_STREAM]))
            out.write(salt)
            out.write(nonce_prefix)
            out.write(struct.pack('>I', chunk_size))
            out.write(bytes([1 if compress else 0]))

            for index, (chunk, is_last) in enumerate(_ChunkedByteReader(source, chunk_size)):
                if index > MAX_CHUNK_INDEX:
                    raise ValueError('File is too large for the current chunk size.')

                nonce = nonce_prefix + struct.pack('>I', index)
                aad = struct.pack('>I?', index, is_last)
                ciphertext = aead.encrypt(nonce, chunk, aad)

                out.write(struct.pack('>I', len(ciphertext)))
                out.write(ciphertext)

        return out_path

    # Decryption (supports both v1 legacy and v2 streaming)
    def decrypt_file(
        self,
        path: str,
        export_dir_path: str = None,
        file_name: str = None,
    ) -> str:
        """
        Streams and decrypts a .crp file back to its original content
        without loading the whole file into memory (for v2 containers;
        legacy v1 containers are still loaded whole, as they always were).

        Args:
            path (str): Path to the .crp file.
            export_dir_path (str, optional): Directory to write the decrypted
                file into. Defaults to 'files/'.
            file_name (str, optional): Name to give the decrypted file.
                Defaults to the name (or relative path) stored inside the
                .crp file; any subdirectories it implies are created under
                export_dir_path.

        Returns:
            str: The path of the written, decrypted file.

        Raises:
            ValueError: If the path is empty.
            FileNotFoundError: If the file does not exist or isn't a .crp file.
            CorruptedFile: If the container is malformed, truncated, or its
                stored name would resolve outside export_dir_path.
            UnsupportedVersion: If the format version is not recognized.
            InvalidKey: If the key is wrong or the data has been tampered with.
        """

        if not path:
            raise ValueError("Path cannot be empty.")

        if not (os.path.isfile(path) and path.endswith('.crp')):
            raise FileNotFoundError('File is not exists or File is not a CRP file')

        with open(path, 'rb') as inp:
            magic = inp.read(len(MAGIC))
            if magic != MAGIC:
                raise CorruptedFile('Not a valid .crp file (bad magic bytes).')

            version_byte = inp.read(1)
            if len(version_byte) != 1:
                raise CorruptedFile('File is too short to be a valid .crp file.')
            version = version_byte[0]

            if version == VERSION_LEGACY:
                decrypted_name, data = self.__decrypt_legacy_v1(inp)
            elif version == VERSION_STREAM:
                decrypted_name, data_iter = self.__open_stream_v2(inp)
                data = None  # written straight to disk below
            else:
                raise UnsupportedVersion(f'Unsupported .crp format version: {version}')

            final_name = file_name or decrypted_name
            export_dir_path = self.__ensure_dir_exists(export_dir_path or 'files/')

            # The stored name may be a relative path ("docs/notes.txt") when
            # the file was part of a directory tree encrypted with
            # `embedded_name`; _safe_join rebuilds it under export_dir_path
            # and refuses anything that would land outside that directory.
            out_path = _safe_join(export_dir_path, final_name)
            parent_dir = os.path.dirname(out_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

            with open(out_path, 'wb') as out:
                if data is not None:
                    out.write(data)
                else:
                    for block in data_iter:
                        out.write(block)

        return out_path

    # v2 (streaming) decryption internals
    def __open_stream_v2(self, inp):
        """
        Parses a v2 header from an already-open file object positioned right
        after the version byte, and returns (file_name, data_blocks_iterator).
        The iterator yields decrypted (and decompressed, if applicable)
        plaintext blocks lazily, so the caller can write them straight to
        disk without buffering the whole file.
        """

        rest_of_header = inp.read(HEADER_SIZE_V2 - len(MAGIC) - 1)
        if len(rest_of_header) != HEADER_SIZE_V2 - len(MAGIC) - 1:
            raise CorruptedFile('File is too short to be a valid .crp file.')

        offset = 0
        salt = rest_of_header[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        nonce_prefix = rest_of_header[offset:offset + NONCE_PREFIX_SIZE]
        offset += NONCE_PREFIX_SIZE
        chunk_size = struct.unpack('>I', rest_of_header[offset:offset + 4])[0]
        offset += 4
        compressed = bool(rest_of_header[offset])

        key = _derive_key(self.__key, salt)
        aead = AESGCM(key)

        name_box = {'name': None}

        def plaintext_blocks():
            decompressor = zlib.decompressobj() if compressed else None
            index = 0
            header_buf = bytearray()
            header_done = False

            len_bytes = inp.read(CHUNK_LEN_FIELD_SIZE)
            while len_bytes:
                if len(len_bytes) != CHUNK_LEN_FIELD_SIZE:
                    raise CorruptedFile('Truncated chunk length header.')

                clen = struct.unpack('>I', len_bytes)[0]
                ciphertext = inp.read(clen)
                if len(ciphertext) != clen:
                    raise CorruptedFile('Truncated chunk data.')

                next_len_bytes = inp.read(CHUNK_LEN_FIELD_SIZE)
                is_last = len(next_len_bytes) == 0
                if 0 < len(next_len_bytes) < CHUNK_LEN_FIELD_SIZE:
                    raise CorruptedFile('Truncated chunk length header.')

                nonce = nonce_prefix + struct.pack('>I', index)
                aad = struct.pack('>I?', index, is_last)

                try:
                    plain = aead.decrypt(nonce, ciphertext, aad)
                except InvalidTag:
                    raise InvalidKey('Invalid Key !')

                if decompressor is not None:
                    plain = decompressor.decompress(plain)
                    if is_last:
                        plain += decompressor.flush()

                if not header_done:
                    header_buf.extend(plain)
                    if len(header_buf) >= 2:
                        name_len = struct.unpack('>H', header_buf[:2])[0]
                        if len(header_buf) >= 2 + name_len:
                            name_box['name'] = header_buf[2:2 + name_len].decode('utf-8')
                            header_done = True
                            remainder = bytes(header_buf[2 + name_len:])
                            if remainder:
                                yield remainder
                    if not header_done:
                        index += 1
                        len_bytes = next_len_bytes
                        continue
                else:
                    yield plain

                index += 1
                len_bytes = next_len_bytes

            if not header_done:
                raise CorruptedFile('Decrypted payload is malformed.')

        blocks = plaintext_blocks()
        first_block = next(blocks, b'')

        def chained():
            if first_block:
                yield first_block
            yield from blocks

        # Force header parsing (it happens lazily on first `next()`) before
        # returning, so `name_box['name']` is populated for the caller.
        return name_box['name'], chained()

    # v1 (legacy, whole-file) decryption internals
    def __decrypt_legacy_v1(self, inp):
        """
        Decrypts a legacy (task 1) whole-file Fernet container. Reads the
        rest of the file into memory, since that format predates chunking.
        """

        rest_of_header = inp.read(HEADER_SIZE_V1 - len(MAGIC) - 1)
        if len(rest_of_header) != SALT_SIZE:
            raise CorruptedFile('File is too short to be a valid .crp file.')

        salt = rest_of_header
        token = inp.read()

        raw_key = _derive_key(self.__key, salt)
        fernet_key = urlsafe_b64encode(raw_key)

        try:
            payload = Fernet(fernet_key).decrypt(token)
        except InvalidToken:
            raise InvalidKey('Invalid Key !')

        if len(payload) < 2:
            raise CorruptedFile('Decrypted payload is malformed.')

        name_len = struct.unpack('>H', payload[:2])[0]
        if len(payload) < 2 + name_len:
            raise CorruptedFile('Decrypted payload is malformed.')

        file_name = payload[2:2 + name_len].decode('utf-8')
        data = payload[2 + name_len:]
        return file_name, data

    @classmethod
    def __ensure_dir_exists(cls, path: str):
        """
        Ensures that a directory exists; if not, creates it.

        Args:
            path (str): The directory path to check.

        Returns:
            str: The path that has been ensured to exist.
        """
        try:
            if not os.path.exists(path):
                os.makedirs(path)

            return path
        except FileExistsError:
            return path
