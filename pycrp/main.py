from cryptography.fernet import Fernet, InvalidToken
from base64 import b64encode
from hashlib import sha256

from exceptions import InvalidKey

import os
import pickle

class Crp:
    """
    A class that provides methods for encrypting and decrypting files using Fernet symmetric encryption.
    """
    
    def __init__(self, key:str):
        """
        Initializes the Crp object with a given encryption key.

        Args:
            key (str): A string that serves as the encryption key.
        
        Raises:
            ValueError: If the provided key is empty.
        """
        
        if not key:
            raise ValueError("An empty key is not Valid input.")
        
        hash = sha256(key.encode()).digest()
        key = b64encode(hash)
        
        self.__f = Fernet(key)
        

    def encrypt(self, data:bytes) -> bytes:
        """
        Encrypts the given byte data.

        Args:
            data (bytes): The data to be encrypted.

        Returns:
            bytes: The encrypted data.

        Raises:
            ValueError: If the provided data is empty.
        """
        
        if not data:
            raise ValueError('Data cannot be empty.')
        return self.__f.encrypt(data)
    
    def decrypt(self, data:bytes) -> bytes:
        """
        Decrypts the given byte data.

        Args:
            data (bytes): The data to be decrypted.

        Returns:
            bytes: The decrypted data.

        Raises:
            ValueError: If the provided data is empty.
        """
        
        if not data:
            raise ValueError('Data cannot be empty.')
        
        try:
            return self.__f.decrypt(data)

        except InvalidToken:
            raise InvalidKey('Invalid Key !')


    
    
    def load_file(self, path:str):
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
    
    def dump_crp(self, file_name:str=None, export_dir_path:str=None):
        """
        Saves the encrypted file data to a .crp file.

        Args:
            file_name (str, optional): The desired name of the output file. If None, the original file name will be used.
            export_dir_path (str, optional): The directory path where the file will be saved. If None, defaults to 'crp-files/'.

        Raises:
            ValueError: If no file has been loaded for encryption.
        """
        
        if hasattr(self, '_crp'):
            if file_name:
                baseName, currentEx = os.path.splitext(file_name)
                
                if currentEx != '.crp':
                    file_name = f'{baseName}.crp'
            else:
                file_name = f"{os.path.splitext(self._crp['file_name'])[0]}.crp"

            if not (export_dir_path and os.path.isdir(export_dir_path)):
                export_dir_path = self.__ensure_dir_exists('crp-files/')
                
                
            path = os.path.join(export_dir_path, file_name)
            data = self.encrypt( pickle.dumps(self._crp) )
            
            with open(path, 'wb') as file:
                file.write(data)
                
            
            return path
        else:
            raise ValueError('Encrypt a file before dumping it.')
    

    def load_crp(self, path:str):
        """
        Loads and decrypts a .crp file to retrieve its original content.

        Args:
            path (str): The path to the .crp file to be loaded.

        Raises:
            ValueError: If the provided path is empty.
            FileNotFoundError: If the file does not exist or is not a .crp file.
        """
        
        if not path:
            raise ValueError("Path cannot be empty.")

        elif os.path.isfile(path) and os.path.exists(path) and path.endswith('.crp'):
            
            with open(path, 'rb') as file:
                data = self.decrypt(file.read())
            
            self._dcrp = pickle.loads(data)
        
        else:
            raise FileNotFoundError('File is not exists or File is not a CRP file') 
 
    def dump_file(self, file_name:str=None, export_dir_path:str=None):
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
    def __ensure_dir_exists(self, path:str):
        """
        Ensures that a directory exists; if not, creates it.

        Args:
            path (str): The directory path to check.

        Returns:
            str: The path that has been ensured to exist.
        """
        if not os.path.exists(path):
            os.makedirs(path)
        
        return path