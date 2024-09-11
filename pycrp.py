from cryptography.fernet import Fernet
from base64 import b64encode
from hashlib import sha256
from termcolor import colored

import os
import pickle

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
    
    
    def load_file(self, path:str):
        if not path:
            raise ValueError("File path cannot be empty.")
        
        elif not os.path.isfile(path):
            raise FileNotFoundError('The file does not exist.')
        
        
        with open(path, 'rb') as file:
            self.__crp = {
                'file_name': os.path.basename(path),
                'data': file.read(),
            }
    
    def dump_crp(self, file_name:str=None, export_dir_path:str=None):
        if hasattr(self, '__crp'):
            if file_name:
                baseName, currentEx = os.path.splitext(file_name)
                
                if currentEx != '.crp':
                    file_name = f'{baseName}.crp'

            if not (export_dir_path and os.path.isdir(export_dir_path)):
                print(colored(f'This Dir does not exist !. File will be saved in "crp-files/"', 'red'))
                export_dir_path = self.__ensure_dir_exists('crp-files/')
                
                
            path = os.path.join(export_dir_path, file_name)
            data = self.encrypt( pickle.dumps(self.__crp) )
            
            with open(path, 'wb') as file:
                file.write(data)
        else:
            raise ValueError('Encrypt a file before dumping it.')
    
    
    def __ensure_dir_exists(self, path:str):
        
        if not os.path.exists(path):
            os.makedirs(path)
        
        return path