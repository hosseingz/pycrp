import os

import pytest
from click.testing import CliRunner

from pycrp.cli import commands, iter_source_files


def _touch(path, content=b'x'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_non_recursive_only_sees_top_level_files(tmp_path):
    _touch(tmp_path / 'top.txt')
    _touch(tmp_path / 'sub' / 'nested.txt')

    found = {rel for rel, _ in iter_source_files(str(tmp_path), recursive=False)}

    assert found == {'top.txt'}


def test_recursive_walks_subdirectories(tmp_path):
    _touch(tmp_path / 'top.txt')
    _touch(tmp_path / 'docs' / 'notes.txt')
    _touch(tmp_path / 'docs' / 'sub' / 'deep.txt')

    found = {rel for rel, _ in iter_source_files(str(tmp_path), recursive=True)}

    assert found == {'top.txt', os.path.join('docs', 'notes.txt'), os.path.join('docs', 'sub', 'deep.txt')}


@pytest.mark.parametrize('ignored_name', ['.DS_Store', 'Thumbs.db', 'desktop.ini', '.directory'])
def test_known_housekeeping_files_are_skipped(tmp_path, ignored_name):
    _touch(tmp_path / 'keep.txt')
    _touch(tmp_path / ignored_name)

    found = {rel for rel, _ in iter_source_files(str(tmp_path), recursive=True)}

    assert found == {'keep.txt'}


def test_symlinks_are_skipped(tmp_path):
    real = tmp_path / 'real.txt'
    _touch(real)
    link = tmp_path / 'link.txt'
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks are not supported in this environment')

    found = {rel for rel, _ in iter_source_files(str(tmp_path), recursive=True)}

    assert found == {'real.txt'}


def test_suffix_filter_only_matches_crp_files(tmp_path):
    _touch(tmp_path / 'a.crp')
    _touch(tmp_path / 'b.txt')

    found = {rel for rel, _ in iter_source_files(str(tmp_path), recursive=True, suffix='.crp')}

    assert found == {'a.crp'}


def test_unreadable_subdirectory_is_reported_but_does_not_abort_scan(tmp_path, monkeypatch, capsys):
    _touch(tmp_path / 'good.txt')

    real_walk = os.walk

    def walk_with_injected_error(top, onerror=None, **kwargs):
        if onerror is not None:
            onerror(OSError(13, 'Permission denied', str(tmp_path / 'locked')))
        yield from real_walk(top, onerror=onerror, **kwargs)

    monkeypatch.setattr('pycrp.cli.os.walk', walk_with_injected_error)

    found = list(iter_source_files(str(tmp_path), recursive=True))

    assert ('good.txt', str(tmp_path / 'good.txt')) in found
    assert 'cannot read' in capsys.readouterr().out


def test_cli_recursive_roundtrip_mirrors_tree(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'readme.txt', b'top level')
    _touch(src / 'docs' / 'notes.txt', b'nested')
    _touch(src / 'docs' / 'sub' / 'deep.txt', b'deeply nested')
    _touch(src / '.DS_Store', b'should be ignored')

    runner = CliRunner()

    enc_result = runner.invoke(commands, [
        'enc', '--key', 'tree-pw', '--dir', str(src), '--export', str(tmp_path / 'crp'), '--recursive',
    ])
    assert enc_result.exit_code == 0, enc_result.output

    dec_result = runner.invoke(commands, [
        'dec', '--key', 'tree-pw', '--dir', str(tmp_path / 'crp'), '--export', str(tmp_path / 'restored'), '--recursive',
    ])
    assert dec_result.exit_code == 0, dec_result.output

    restored = tmp_path / 'restored'
    assert (restored / 'readme.txt').read_bytes() == b'top level'
    assert (restored / 'docs' / 'notes.txt').read_bytes() == b'nested'
    assert (restored / 'docs' / 'sub' / 'deep.txt').read_bytes() == b'deeply nested'
    assert not (restored / '.DS_Store').exists()


def test_cli_non_recursive_leaves_subdirectories_untouched(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'top.txt', b'top')
    _touch(src / 'sub' / 'nested.txt', b'nested')

    runner = CliRunner()
    result = runner.invoke(commands, [
        'enc', '--key', 'pw', '--dir', str(src), '--export', str(tmp_path / 'crp'),
    ])

    assert result.exit_code == 0
    produced = {p.name for p in (tmp_path / 'crp').glob('*.crp')}
    assert produced == {'top.crp'}


def test_cli_batch_continues_after_one_file_fails(tmp_path, monkeypatch):
    src = tmp_path / 'src'
    _touch(src / 'good_a.txt', b'a')
    _touch(src / 'bad.txt', b'b')
    _touch(src / 'good_z.txt', b'z')

    from pycrp.main import Crp as RealCrp
    real_encrypt_file = RealCrp.encrypt_file

    def flaky_encrypt_file(self, path, *args, **kwargs):
        if os.path.basename(path) == 'bad.txt':
            raise PermissionError('simulated: no read access')
        return real_encrypt_file(self, path, *args, **kwargs)

    monkeypatch.setattr('pycrp.cli.Crp.encrypt_file', flaky_encrypt_file)

    runner = CliRunner()
    result = runner.invoke(commands, [
        'enc', '--key', 'pw', '--dir', str(src), '--export', str(tmp_path / 'crp'),
    ])

    assert result.exit_code == 0
    produced = {p.stem for p in (tmp_path / 'crp').glob('*.crp')}
    assert produced == {'good_a', 'good_z'}
    assert 'Permission denied' in result.output
    assert 'Skipped (permission denied): 1' in result.output
    assert 'Encrypted: 2' in result.output
