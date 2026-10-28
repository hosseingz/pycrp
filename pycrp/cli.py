from .exceptions import InvalidKey, CorruptedFile, UnsupportedVersion
from termcolor import colored
from pycrp import Crp
import click
import os

# Housekeeping files that OSes and file managers drop into folders on their
# own; these are never something a user meant to encrypt, so a recursive
# scan skips them rather than making a .crp out of each one.
IGNORED_NAMES = frozenset({'.DS_Store', 'Thumbs.db', 'desktop.ini', '.directory'})


def _warn_walk_error(error: OSError):
    click.echo(f'{colored("warning", "yellow")}: cannot read {error.filename}: {error.strerror}')


def iter_source_files(base_dir: str, recursive: bool, suffix: str = None):
    """
    Yields (relative_path, absolute_path) for files under base_dir.

    Non-recursive mode only looks at base_dir's immediate contents, matching
    the tool's original behaviour. Recursive mode walks subdirectories too
    and reports, rather than raises on, directories it can't read. Either
    way, symlinks and known OS housekeeping files are skipped, and `suffix`
    (when given) filters out anything that can't be a match up front.
    """

    def is_wanted(name: str, abs_path: str) -> bool:
        if name in IGNORED_NAMES or os.path.islink(abs_path):
            return False
        if suffix and not name.endswith(suffix):
            return False
        return os.path.isfile(abs_path)

    if not recursive:
        for name in sorted(os.listdir(base_dir)):
            abs_path = os.path.join(base_dir, name)
            if is_wanted(name, abs_path):
                yield name, abs_path
        return

    for root, subdirs, files in os.walk(base_dir, onerror=_warn_walk_error):
        # Don't descend into symlinked directories: os.walk would otherwise
        # follow them outside the tree being processed, possibly looping.
        subdirs[:] = sorted(d for d in subdirs if not os.path.islink(os.path.join(root, d)))

        for name in sorted(files):
            abs_path = os.path.join(root, name)
            if is_wanted(name, abs_path):
                yield os.path.relpath(abs_path, base_dir), abs_path


@click.group
def commands():
    pass


@click.command()
@click.argument('key', required=1)
@click.option('-d', '--dir', type=click.Path(exists=True), help='Specifies the directory from witch to load files.')
@click.option('-ex', '--export', type=click.Path(exists=True), help='The directory path where the file will be saved.')
@click.option('-r', '--recursive', is_flag=True, default=False,
              help='Also encrypt files in subdirectories, mirroring the folder structure in the export directory.')
def enc(key, dir, export, recursive):
    """Encrypt your files using the provided KEY.

    This command will encrypt all files in the specified directory (or the current directory if not specified)
    and save the encrypted versions in the export directory (or current directory if not specified).
    
    Usage:
        enc SECRET_KEY --dir /path/to/directory --export /path/to/export
        enc SECRET_KEY --dir /path/to/directory --export /path/to/export --recursive
    """

    crp = Crp(key)
    base_dir = dir if dir is not None else '.'
    export_dir = export or 'crp-files/'

    for rel_path, abs_path in iter_source_files(base_dir, recursive):
        try:
            # The original directory layout is recorded inside the container
            # itself (embedded_name), so decryption can rebuild it later
            # regardless of how the resulting .crp files get moved around;
            # mirroring it in export_dir as well just keeps this run's
            # output tidy and collision-free.
            out_subdir = os.path.join(export_dir, os.path.dirname(rel_path))
            out_path = crp.encrypt_file(
                abs_path,
                export_dir_path=out_subdir,
                embedded_name=rel_path,
            )

            click.echo(f"{rel_path}: {colored('saved', 'green')} -> {out_path}")

        except PermissionError:
            click.echo(f'{rel_path}: {colored("Permission denied, skipped.", "yellow")}')
        except FileNotFoundError:
            click.echo(f'{rel_path}: {colored("Not Found !", "red")}')
        except OSError as error:
            click.echo(f'{rel_path}: {colored(f"Skipped ({error.strerror or error}).", "yellow")}')


@click.command()
@click.argument('key', required=1)
@click.option('-d', '--dir', type=click.Path(exists=True), help='Specifies the directory from witch to load files.')
@click.option('-ex', '--export', type=click.Path(exists=True), help='The directory path where the file will be saved.')
@click.option('-r', '--recursive', is_flag=True, default=False,
              help='Also look for .crp files in subdirectories and restore the original folder structure.')
def dec(key, dir, export, recursive):
    """Decrypt your files using the provided KEY.

    This command will decrypt all .crp files in the specified directory (or the current directory if not specified)
    and save the decrypted versions in the export directory (or current directory if not specified).
    
    Usage:
        dec SECRET_KEY --dir /path/to/directory --export /path/to/export
        dec SECRET_KEY --dir /path/to/directory --export /path/to/export --recursive
    """

    crp = Crp(key)
    base_dir = dir if dir is not None else '.'
    export_dir = export or 'files/'

    for rel_path, abs_path in iter_source_files(base_dir, recursive, suffix='.crp'):
        try:
            # The directory a file is restored into comes from the name
            # stored inside the container, not from where the .crp file
            # happens to sit on disk, so the original tree comes back even
            # if these .crp files were collected into a single flat folder.
            out_path = crp.decrypt_file(abs_path, export_dir_path=export_dir)

            click.echo(f"{rel_path}: {colored('saved', 'green')} -> {out_path}")
        except InvalidKey:
            click.echo(f'{rel_path}: {colored("Invalid Key for this file !", "red")}')
        except (CorruptedFile, UnsupportedVersion) as e:
            click.echo(f'{rel_path}: {colored(f"Corrupted or unsupported .crp file ({e})", "red")}')
        except PermissionError:
            click.echo(f'{rel_path}: {colored("Permission denied, skipped.", "yellow")}')
        except FileNotFoundError:
            click.echo(f'{rel_path}: {colored("Not Found or Not a Crp File !", "red")}')


commands.add_command(enc)
commands.add_command(dec)

if __name__ == '__main__':

    commands()
