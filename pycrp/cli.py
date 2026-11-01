from .exceptions import InvalidKey, CorruptedFile, UnsupportedVersion, ShredError
from .constants import DEFAULT_SHRED_PASSES
from .shred import secure_delete
from termcolor import colored
from pycrp import Crp
import click
import os

# Housekeeping files that OSes and file managers drop into folders on their
# own; these are never something a user meant to encrypt, so a recursive
# scan skips them rather than making a .crp out of each one.
IGNORED_NAMES = frozenset({'.DS_Store', 'Thumbs.db', 'desktop.ini', '.directory'})

KEY_ENVVAR = 'PYCRP_KEY'


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


class BatchReport:
    """
    Tallies per-file outcomes for one enc/dec run and renders a short
    recap once the batch finishes, so a long run doesn't just scroll a
    wall of interleaved status lines off the screen with no way to tell,
    at a glance, what actually needs attention.
    """

    def __init__(self):
        self._by_status = {}

    def record(self, status: str, rel_path: str, detail: str = ''):
        self._by_status.setdefault(status, []).append((rel_path, detail))

    def render(self, labels: dict):
        total = sum(len(entries) for entries in self._by_status.values())
        if total == 0:
            click.echo('No files matched.')
            return

        click.echo('')
        click.echo(f'--- {total} file(s) processed ---')
        for status, label in labels.items():
            entries = self._by_status.get(status, [])
            if not entries:
                continue
            click.echo(f'{label}: {len(entries)}')
            if status != 'ok':
                for rel_path, detail in entries:
                    suffix = f' ({detail})' if detail else ''
                    click.echo(f'    {rel_path}{suffix}')


@click.group
def commands():
    pass


@click.command()
@click.option('--key', '-k', prompt=True, hide_input=True, confirmation_prompt=True, envvar=KEY_ENVVAR,
              help=f'Encryption passphrase. Prompted (twice, to catch typos) if {KEY_ENVVAR} is not set.')
@click.option('-d', '--dir', type=click.Path(exists=True), help='Specifies the directory from witch to load files.')
@click.option('-ex', '--export', type=click.Path(), help='The directory path where the file will be saved; created automatically if missing.')
@click.option('-r', '--recursive', is_flag=True, default=False,
              help='Also encrypt files in subdirectories, mirroring the folder structure in the export directory.')
@click.option('--shred', is_flag=True, default=False,
              help='Permanently overwrite and delete each source file once it has been encrypted. '
                   'See the README for what this can and cannot guarantee on SSDs.')
@click.option('--shred-passes', type=click.IntRange(min=1), default=DEFAULT_SHRED_PASSES, show_default=True,
              help='Overwrite passes before deletion. Ignored unless --shred is set.')
@click.option('-y', '--yes', is_flag=True, default=False,
              help='Skip the confirmation prompt before shredding source files.')
def enc(key, dir, export, recursive, shred, shred_passes, yes):
    """Encrypt your files using a passphrase.

    The passphrase is read from a hidden prompt (entered twice, to catch
    typos before they lock you out of your own files), or from the
    PYCRP_KEY environment variable for non-interactive use.

    This command will encrypt all files in the specified directory (or the current directory if not specified)
    and save the encrypted versions in the export directory (or current directory if not specified).

    Usage:
        enc --dir /path/to/directory --export /path/to/export
        enc --dir /path/to/directory --export /path/to/export --recursive
        enc --dir /path/to/directory --export /path/to/export --shred --yes
    """

    crp = Crp(key)
    base_dir = dir if dir is not None else '.'
    export_dir = export or 'crp-files/'
    report = BatchReport()

    files = list(iter_source_files(base_dir, recursive))

    if shred and files and not yes:
        click.confirm(
            f'This will permanently overwrite and delete {len(files)} source file(s) '
            f'after encrypting them. This cannot be undone. Continue?',
            abort=True,
        )

    for index, (rel_path, abs_path) in enumerate(files, start=1):
        label = f'[{index}/{len(files)}] {rel_path}'
        size = os.path.getsize(abs_path)

        try:
            with click.progressbar(length=max(size, 1), label=label) as bar:
                out_subdir = os.path.join(export_dir, os.path.dirname(rel_path))
                out_path = crp.encrypt_file(
                    abs_path,
                    export_dir_path=out_subdir,
                    embedded_name=rel_path,
                    progress_callback=bar.update,
                )

            click.echo(f"{rel_path}: {colored('saved', 'green')} -> {out_path}")

            if shred:
                try:
                    secure_delete(abs_path, passes=shred_passes)
                    click.echo(f"{rel_path}: {colored('source wiped', 'green')}")
                except ShredError as error:
                    click.echo(f'{rel_path}: {colored(f"source NOT wiped ({error})", "yellow")}')
                    report.record('shred_failed', rel_path, str(error))
                    continue

            report.record('ok', rel_path)

        except PermissionError:
            click.echo(f'{rel_path}: {colored("Permission denied, skipped.", "yellow")}')
            report.record('permission', rel_path, 'permission denied')
        except FileNotFoundError:
            click.echo(f'{rel_path}: {colored("Not Found !", "red")}')
            report.record('other', rel_path, 'not found')
        except OSError as error:
            click.echo(f'{rel_path}: {colored(f"Skipped ({error.strerror or error}).", "yellow")}')
            report.record('other', rel_path, error.strerror or str(error))

    report.render({
        'ok': 'Encrypted',
        'shred_failed': 'Encrypted, but source NOT wiped',
        'permission': 'Skipped (permission denied)',
        'other': 'Skipped (other errors)',
    })


@click.command()
@click.option('--key', '-k', prompt=True, hide_input=True, envvar=KEY_ENVVAR,
              help=f'Decryption passphrase. Prompted if {KEY_ENVVAR} is not set.')
@click.option('-d', '--dir', type=click.Path(exists=True), help='Specifies the directory from witch to load files.')
@click.option('-ex', '--export', type=click.Path(), help='The directory path where the file will be saved; created automatically if missing.')
@click.option('-r', '--recursive', is_flag=True, default=False,
              help='Also look for .crp files in subdirectories and restore the original folder structure.')
def dec(key, dir, export, recursive):
    """Decrypt your files using the passphrase they were encrypted with.

    The passphrase is read from a hidden prompt, or from the PYCRP_KEY
    environment variable for non-interactive use. Unlike `enc`, it is
    not asked for twice: typing it the same way twice would not tell us
    whether it is actually the right one.

    This command will decrypt all .crp files in the specified directory (or the current directory if not specified)
    and save the decrypted versions in the export directory (or current directory if not specified).

    Usage:
        dec --dir /path/to/directory --export /path/to/export
        dec --dir /path/to/directory --export /path/to/export --recursive
    """

    crp = Crp(key)
    base_dir = dir if dir is not None else '.'
    export_dir = export or 'files/'
    report = BatchReport()

    files = list(iter_source_files(base_dir, recursive, suffix='.crp'))
    for index, (rel_path, abs_path) in enumerate(files, start=1):
        label = f'[{index}/{len(files)}] {rel_path}'
        size = os.path.getsize(abs_path)

        try:
            with click.progressbar(length=max(size, 1), label=label) as bar:
                out_path = crp.decrypt_file(abs_path, export_dir_path=export_dir, progress_callback=bar.update)

            click.echo(f"{rel_path}: {colored('saved', 'green')} -> {out_path}")
            report.record('ok', rel_path)

        except InvalidKey:
            click.echo(f'{rel_path}: {colored("Invalid Key for this file !", "red")}')
            report.record('invalid_key', rel_path)
        except (CorruptedFile, UnsupportedVersion) as e:
            click.echo(f'{rel_path}: {colored(f"Corrupted or unsupported .crp file ({e})", "red")}')
            report.record('corrupted', rel_path, str(e))
        except PermissionError:
            click.echo(f'{rel_path}: {colored("Permission denied, skipped.", "yellow")}')
            report.record('permission', rel_path, 'permission denied')
        except FileNotFoundError:
            click.echo(f'{rel_path}: {colored("Not Found or Not a Crp File !", "red")}')
            report.record('other', rel_path, 'not found')

    report.render({
        'ok': 'Decrypted',
        'invalid_key': 'Wrong key',
        'corrupted': 'Corrupted or unsupported',
        'permission': 'Skipped (permission denied)',
        'other': 'Skipped (other errors)',
    })


commands.add_command(enc)
commands.add_command(dec)

if __name__ == '__main__':

    commands()
