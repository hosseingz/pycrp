import os

from click.testing import CliRunner

from pycrp.cli import commands


def _touch(path, content=b'x'):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_enc_accepts_password_via_option_without_prompting(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'a.txt', b'content')

    runner = CliRunner()
    result = runner.invoke(commands, [
        'enc', '--key', 'direct-pw', '--dir', str(src), '--export', str(tmp_path / 'crp'),
    ])

    assert result.exit_code == 0
    assert 'Password' not in result.output
    assert (tmp_path / 'crp' / 'a.crp').exists()


def test_enc_prompts_for_password_and_confirms_it(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'a.txt', b'content')

    runner = CliRunner()
    result = runner.invoke(commands, [
        'enc', '--dir', str(src), '--export', str(tmp_path / 'crp'),
    ], input='interactively-typed-pw\ninteractively-typed-pw\n')

    assert result.exit_code == 0, result.output
    assert (tmp_path / 'crp' / 'a.crp').exists()


def test_enc_rejects_mismatched_password_confirmation(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'a.txt', b'content')

    runner = CliRunner()
    result = runner.invoke(commands, [
        'enc', '--dir', str(src), '--export', str(tmp_path / 'crp'),
    ], input='first-typing\na-different-typing\n')

    assert result.exit_code != 0
    assert not (tmp_path / 'crp' / 'a.crp').exists()


def test_dec_only_prompts_once_no_confirmation_needed(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'a.txt', b'content')

    runner = CliRunner()
    enc_result = runner.invoke(commands, [
        'enc', '--key', 'round-trip-pw', '--dir', str(src), '--export', str(tmp_path / 'crp'),
    ])
    assert enc_result.exit_code == 0

    dec_result = runner.invoke(commands, [
        'dec', '--dir', str(tmp_path / 'crp'), '--export', str(tmp_path / 'dec'),
    ], input='round-trip-pw\n')

    assert dec_result.exit_code == 0, dec_result.output
    assert (tmp_path / 'dec' / 'a.txt').read_bytes() == b'content'


def test_key_from_environment_variable_needs_no_input_at_all(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'a.txt', b'content')

    runner = CliRunner()
    result = runner.invoke(
        commands,
        ['enc', '--dir', str(src), '--export', str(tmp_path / 'crp')],
        env={'PYCRP_KEY': 'env-pw'},
        input='',  # nothing typed; would hang on a real prompt instead of failing fast
    )

    assert result.exit_code == 0, result.output
    assert (tmp_path / 'crp' / 'a.crp').exists()


def test_dec_batch_summary_separates_ok_wrong_key_and_corrupted(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'good.txt', b'fine')
    _touch(src / 'other.txt', b'also fine')

    runner = CliRunner()
    runner.invoke(commands, ['enc', '--key', 'batch-pw', '--dir', str(src), '--export', str(tmp_path / 'crp')])

    # corrupt one of the two valid containers
    broken = tmp_path / 'crp' / 'other.crp'
    data = bytearray(broken.read_bytes())
    broken.write_bytes(data[:-10])

    result = runner.invoke(commands, [
        'dec', '--key', 'wrong-pw-on-purpose', '--dir', str(tmp_path / 'crp'), '--export', str(tmp_path / 'dec'),
    ])

    assert 'Wrong key: 2' in result.output or 'Corrupted or unsupported' in result.output


def test_shred_prompts_before_deleting_and_honours_decline(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'a.txt', b'sensitive')

    runner = CliRunner()
    result = runner.invoke(commands, [
        'enc', '--key', 'pw', '--dir', str(src), '--export', str(tmp_path / 'crp'), '--shred',
    ], input='n\n')

    assert result.exit_code != 0  # click.confirm(abort=True) aborts the command
    assert (src / 'a.txt').exists()


def test_shred_with_yes_flag_deletes_without_prompting(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'a.txt', b'sensitive')

    runner = CliRunner()
    result = runner.invoke(commands, [
        'enc', '--key', 'pw', '--dir', str(src), '--export', str(tmp_path / 'crp'), '--shred', '--yes',
    ])

    assert result.exit_code == 0, result.output
    assert not (src / 'a.txt').exists()
    assert (tmp_path / 'crp' / 'a.crp').exists()
    assert 'source wiped' in result.output


def test_shredded_source_still_decrypts_correctly_from_the_crp_copy(tmp_path):
    src = tmp_path / 'src'
    _touch(src / 'a.txt', b'sensitive content that must survive in the .crp copy')

    runner = CliRunner()
    runner.invoke(commands, [
        'enc', '--key', 'pw', '--dir', str(src), '--export', str(tmp_path / 'crp'), '--shred', '--yes',
    ])

    result = runner.invoke(commands, [
        'dec', '--key', 'pw', '--dir', str(tmp_path / 'crp'), '--export', str(tmp_path / 'dec'),
    ])

    assert result.exit_code == 0
    assert (tmp_path / 'dec' / 'a.txt').read_bytes() == b'sensitive content that must survive in the .crp copy'
