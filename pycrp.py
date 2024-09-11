from cryptography.fernet import Fernet
from base64 import b64encode
from hashlib import sha256


class Crp:
    def __init__(self, key:str):
        
        if not key:
            raise ValueError("An empty key is not Valid input.")
        
        hash = sha256(key.encode()).digest()
        key = b64encode(hash)
        
        self.__f = Fernet(key)
        

    def encrypt(self, data:bytes) -> bytes:
        if not data:
            raise ValueError('Data cannot be empty.')
        return self.__f.encrypt(data)
    
    def decrypt(self, data:bytes) -> bytes:
        if not data:
            raise ValueError('Data cannot be empty.')
        return self.__f.decrypt(data)
        