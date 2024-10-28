# Crp Encryption Tool 🔐

Welcome to **Pycrp**, a simple yet effective command-line tool for encrypting and decrypting files using symmetric encryption 
**[`Fernet`](https://github.com/pyca/cryptography)**. This tool is designed to protect your files with a key you provide and securely save or retrieve them from encrypted `.crp` files.

## Features ✨
- **Encrypt Files**: Secure your files by encrypting them with a key.
- **Decrypt Files**: Retrieve your encrypted files with the correct key.
- **Simple CLI Interface**: Use easy-to-remember commands to encrypt or decrypt files in bulk.


## Installation ⬇️

To get started:

```bash
pip install pycrp
```

## Usage 🚀

This tool provides two main commands: `enc` to encrypt files and `dec` to decrypt them.

### Encrypt Files 🔒

To encrypt files in a directory, use the `enc` command:

```bash
pycrp enc <key> -d <directory> -ex <export_directory>
```

- `<key>`: The encryption key.
- `-d <directory>`: The directory where the files to encrypt are located. If omitted, it defaults to the current directory.
- `-ex <export_directory>`: The directory where the encrypted `.crp` files will be saved. If omitted, it defaults to `crp-files/`.

Example:

```bash
pycrp enc "my-secret-key" -d ./myfiles -ex ./encrypted-files
```

### Decrypt Files 🔓

To decrypt previously encrypted `.crp` files, use the `dec` command:

```bash
pycrp dec <key> -d <directory> -ex <export_directory>
```

- `<key>`: The decryption key (must be the same key used to encrypt the files).
- `-d <directory>`: The directory where the `.crp` files are located. Defaults to the current directory if omitted.
- `-ex <export_directory>`: The directory where the decrypted files will be saved. Defaults to `files/`.

Example:

```bash
pycrp dec "my-secret-key" -d ./encrypted-files -ex ./decrypted-files
```


## Code Overview 🛠️

### `Crp` Class

The `Crp` class provides all the core functionality:

- **`__init__(key: str)`**: Initializes the encryption/decryption object with a specified key.
- **`encrypt( bytes) -> bytes`**: Encrypts byte data using the Fernet symmetric encryption.
- **`decrypt( bytes) -> bytes`**: Decrypts previously encrypted byte data.
- **`load_file(path: str)`**: Loads the file data to prepare it for encryption.
- **`dump_crp(file_name: str = None, export_dir_path: str = None)`**: Saves the encrypted data to a `.crp` file.
- **`load_crp(path: str)`**: Loads and decrypts a `.crp` file.
- **`dump_file(file_name: str = None, export_dir_path: str = None)`**: Saves the decrypted data to a file.

### Example Usage in Python 🐍

Here's how to use the `Crp` class in your Python code for encrypting and decrypting a file:

```python
from pycrp import Crp

# Initialize with an encryption key
key = "my-secret-key"
crp = Crp(key)

# Encrypt a file
file_path = "path/to/your/file.txt"
crp.load_file(file_path)
encrypted_path = crp.dump_crp(export_dir_path="encrypted_files")
print(f"File encrypted and saved to {encrypted_path}")

# Decrypt the previously encrypted file
crp.load_crp(encrypted_path)
decrypted_path = crp.dump_file(export_dir_path="decrypted_files")
print(f"File decrypted and saved to {decrypted_path}")
```

## Contributing 🤝

Feel free to open issues and submit pull requests. Contributions are welcome!

## License 📄

This project is licensed under the MIT License.
