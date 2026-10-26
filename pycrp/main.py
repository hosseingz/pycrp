from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken
from base64 import urlsafe_b64encode

from .exceptions import InvalidKey, CorruptedFile, UnsupportedVersion
from .constants import (
    MAGIC, VERSION, SALT_SIZE, KEY_LEN,
    SCRYPT_N, SCRYPT_R, SCRYPT_P, HEADER_SIZE,
)

import os
import struct


def _derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a Fernet-compatible key (32 url-safe-base64-encoded bytes) from a
    password and a salt using scrypt, a memory-hard KDF. This replaces the
    previous single-pass sha256(password) scheme, which had no salt and was
    cheap to brute-force or precompute (rainbow tables / GPU cracking).
    """
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    raw_key = kdf.derive(password.encode('utf-8'))
    return urlsafe_b64encode(raw_key)


class Crp:
    """
    A class that provides methods for encrypting and decrypting files using
    Fernet symmetric encryption, with a random salt per operation and a
    scrypt-derived key (instead of a bare sha256 hash of the password).

    Container format, see constants.py for details:
        MAGIC(4) + VERSION(1) + SALT(16) + FERNET_TOKEN(...)

    The previous implementation stored file metadata (name + bytes) with
    `pickle`, which allows arbitrary code execution if a malicious/corrupted
    .crp file is ever loaded. This version replaces pickle with a tiny,
    fixed binary layout (2-byte filename length + utf-8 filename + raw
    bytes) that is encrypted inside the Fernet token, so loading a .crp file
    can no longer execute attacker-controlled code.
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

        # The raw password is kept (not pre-hashed) because each encrypt()
        # call derives its own key from a fresh random salt.
        self.__key = key

    def __fernet_for_salt(self, salt: bytes) -> Fernet:
        return Fernet(_derive_key(self.__key, salt))

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypts the given byte data with a freshly generated random salt.

        Args:
            data (bytes): The data to be encrypted.

        Returns:
            bytes: MAGIC + VERSION + SALT + Fernet token.

        Raises:
            ValueError: If the provided data is empty.
        """

        if not data:
            raise ValueError('Data cannot be empty.')

        salt = os.urandom(SALT_SIZE)
        token = self.__fernet_for_salt(salt).encrypt(data)

        return MAGIC + bytes([VERSION]) + salt + token

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts data produced by `encrypt`.

        Args:
            data (bytes): The data to be decrypted.

        Returns:
            bytes: The decrypted data.

        Raises:
            ValueError: If the provided data is empty.
            CorruptedFile: If the data is too short or has a bad magic header.
            UnsupportedVersion: If the data was produced by an incompatible format version.
            InvalidKey: If the key is wrong or the data has been tampered with.
        """

        if not data:
            raise ValueError('Data cannot be empty.')

        if len(data) < HEADER_SIZE:
            raise CorruptedFile('File is too short to be a valid .crp file.')

        if data[:len(MAGIC)] != MAGIC:
            raise CorruptedFile('Not a valid .crp file (bad magic bytes).')

        offset = len(MAGIC)
        version = data[offset]
        offset += 1
        if version != VERSION:
            raise UnsupportedVersion(f'Unsupported .crp format version: {version}')

        salt = data[offset:offset + SALT_SIZE]
        offset += SALT_SIZE
        token = data[offset:]

        try:
            return self.__fernet_for_salt(salt).decrypt(token)
        except InvalidToken:
            raise InvalidKey('Invalid Key !')

    def load_file(self, path: str):
        """
        This function reads the file data and prepares it for subsequent encryption operations.
        It raises an error if the provided file path is invalid or if the file does not exist.

        Args:
            path (str): The path to the file to be loaded.

        Raises:
            ValueError: If the file path is empty.
            FileNotFoundError: If the specified file does not exist or is not a file.
        """

        if not path:
            raise ValueError("File path cannot be empty.")

        elif os.path.exists(path) and not os.path.isfile(path):
            raise FileNotFoundError('The file does not exist.')

        with open(path, 'rb') as file:
            self._crp = {
                'file_name': os.path.basename(path),
                'data': file.read(),
            }

    def dump_crp(self, file_name: str = None, export_dir_path: str = None):
        """
        Saves the encrypted file data to a .crp file.

        Args:
            file_name (str, optional): The desired name of the output file. If None, the original file name will be used.
            export_dir_path (str, optional): The directory path where the file will be saved. If None, defaults to 'crp-files/'.

        Raises:
            ValueError: If no file has been loaded for encryption.
        """

        if not hasattr(self, '_crp'):
            raise ValueError('Encrypt a file before dumping it.')

        if file_name:
            baseName, currentEx = os.path.splitext(file_name)

            if currentEx != '.crp':
                file_name = f'{baseName}.crp'
        else:
            file_name = f"{os.path.splitext(self._crp['file_name'])[0]}.crp"

        if not export_dir_path:
            export_dir_path = self.__ensure_dir_exists('crp-files/')
        else:
            export_dir_path = self.__ensure_dir_exists(export_dir_path)

        path = os.path.join(export_dir_path, file_name)

        # Binary metadata header (replaces pickle): 2-byte big-endian
        # filename length, the utf-8 filename, then the raw file bytes.
        # This whole payload is encrypted together, so the filename stays
        # confidential too.
        original_name = self._crp['file_name'].encode('utf-8')
        if len(original_name) > 0xFFFF:
            raise ValueError('File name is too long to be stored.')

        payload = struct.pack('>H', len(original_name)) + original_name + self._crp['data']
        data = self.encrypt(payload)

        with open(path, 'wb') as file:
            file.write(data)

        return path

    def load_crp(self, path: str):
        """
        Loads and decrypts a .crp file to retrieve its original content.

        Args:
            path (str): The path to the .crp file to be loaded.

        Raises:
            ValueError: If the provided path is empty.
            FileNotFoundError: If the file does not exist or is not a .crp file.
            CorruptedFile: If the file content is not a valid .crp container.
            UnsupportedVersion: If the file was produced by an incompatible format version.
            InvalidKey: If the key is wrong.
        """

        if not path:
            raise ValueError("Path cannot be empty.")

        if os.path.isfile(path) and path.endswith('.crp'):

            with open(path, 'rb') as file:
                payload = self.decrypt(file.read())

            if len(payload) < 2:
                raise CorruptedFile('Decrypted payload is malformed.')

            name_len = struct.unpack('>H', payload[:2])[0]
            if len(payload) < 2 + name_len:
                raise CorruptedFile('Decrypted payload is malformed.')

            file_name = payload[2:2 + name_len].decode('utf-8')
            data = payload[2 + name_len:]

            self._dcrp = {
                'file_name': file_name,
                'data': data,
            }

        else:
            raise FileNotFoundError('File is not exists or File is not a CRP file')

    def dump_file(self, file_name: str = None, export_dir_path: str = None):
        """
        Saves the decrypted file data to the specified output path.

        Args:
            file_name (str, optional): The desired name for the output file. Defaults to the original file name if None.
            export_dir_path (str, optional): The directory path where the file will be saved. If None, defaults to 'files/'.

        Raises:
            ValueError: If no file has been decrypted for dumping.
        """

        if hasattr(self, '_dcrp'):
            try:
                if not file_name:
                    file_name = self._dcrp['file_name']

                if not (export_dir_path and os.path.isdir(export_dir_path)):
                    export_dir_path = self.__ensure_dir_exists('files/')

                path = os.path.join(export_dir_path, file_name)

                with open(path, 'wb') as file:
                    file.write(self._dcrp['data'])

                return path

            except Exception as e:
                print(f'Error: {e}')
        else:
            raise ValueError('Decrypt a file before dumping it.')

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
