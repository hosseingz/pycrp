class InvalidKey(Exception):
    """Raised when decryption fails because the supplied key is wrong."""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class CorruptedFile(Exception):
    """Raised when a .crp file is too short, truncated, or has a bad magic header."""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class UnsupportedVersion(Exception):
    """Raised when a .crp file was produced by a newer/older, incompatible format version."""
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
