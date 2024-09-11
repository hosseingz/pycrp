from termcolor import colored
from pycrp import Crp
import click
import os


@click.group
def commands():
    pass


@click.command()
@click.argument('key', required=1)
@click.option('-d', '--dir', type=click.Path(exists=True), help='Specifies the directory from witch to load files.')
@click.option('-ex', '--export', type=click.Path(exists=True), help='The directory path where the file will be saved.')
def enc(key, dir, export):
    """Encrypt your files using the provided KEY.

    This command will encrypt all files in the specified directory (or the current directory if not specified)
    and save the encrypted versions in the export directory (or current directory if not specified).
    
    Usage:
        enc SECRET_KEY --dir /path/to/directory --export /path/to/export
    """
    
    crp = Crp(key)
    files = os.listdir(dir if dir is not None else '.')
    files = list(filter(lambda f: os.path.isfile(f) , files))
    
    for file in files:
        path = os.path.join(dir if dir is not None else '.', file)
        
        try:
            crp.load_file(path)
            crp.dump_crp(export_dir_path=export)
        except FileNotFoundError:
            print(f'{file}: {colored("Not Found !", "red")}')

 

@click.command()
@click.argument('key', required=1)
@click.option('-d', '--dir', type=click.Path(exists=True), help='Specifies the directory from witch to load files.')
@click.option('-ex', '--export', type=click.Path(exists=True), help='The directory path where the file will be saved.')
def dec(key, dir, export):
    """Decrypt your files using the provided KEY.

    This command will decrypt all .crp files in the specified directory (or the current directory if not specified)
    and save the decrypted versions in the export directory (or current directory if not specified).
    
    Usage:
        dec SECRET_KEY --dir /path/to/directory --export /path/to/export
    """

    crp = Crp(key)
    files = os.listdir(dir if dir is not None else '.')
    files = list(filter(lambda f: os.path.isfile(f) , files))
    
    for file in files:
        path = os.path.join(dir if dir is not None else '.', file)
        try:
            crp.load_crp(path)
            crp.dump_file(export_dir_path=export)
        except FileNotFoundError:
            print(f'{file}: {colored("Not Found or Not a Crp File !", "red")}')


commands.add_command(enc)
commands.add_command(dec)
    
if __name__ == '__main__':
    
    commands()