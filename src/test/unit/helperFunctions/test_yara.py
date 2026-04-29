import pytest
import yara

from helperFunctions.yara import (
    Match,
    StringInstance,
    StringMatch,
    _rules_are_compiled,
    compile_plugin_yara_signatures,
    compile_rules,
    get_all_matched_strings,
    scan_dir,
    scan_file,
    scan_files,
)
from test.common_helper import get_test_data_dir

TEST_DIR = get_test_data_dir() / 'yara_test_dir'
TEST_FILE = get_test_data_dir() / 'yara_test_file'
COMPRESSED_FILE = get_test_data_dir() / 'container/test.zip'


@pytest.fixture
def temp_compiled_rules(tmp_path):
    output_path = tmp_path / 'compiled.yc'
    source = TEST_DIR / 'test.yara'
    compile_rules(source, output_path)
    return output_path


@pytest.fixture
def temp_compiled_rules_from_dir(tmp_path):
    output_path = tmp_path / 'compiled_dir.yc'
    compile_rules(TEST_DIR, output_path)
    return output_path


def test_rules_are_compiled_compiled_file(temp_compiled_rules):
    assert _rules_are_compiled(TEST_DIR / 'test.yara') is False
    assert _rules_are_compiled(temp_compiled_rules) is True


def test_compile_rules(tmp_path):
    output_path = tmp_path / 'compiled_dir.yc'

    compile_rules(TEST_DIR, output_path)

    assert output_path.exists()
    assert output_path.stat().st_size > 0
    assert _rules_are_compiled(output_path)


def test_scan_file_match(temp_compiled_rules):
    matches = list(scan_file(temp_compiled_rules, TEST_FILE))

    assert len(matches) >= 1
    assert matches[0].rule == 'test_string_rule'
    assert len(matches[0].strings) >= 1


def test_scan_file_no_match(temp_compiled_rules):
    matches = list(scan_file(temp_compiled_rules, COMPRESSED_FILE))

    assert matches == []


def test_scan_dir(temp_compiled_rules, tmp_path):
    """Test scanning a directory recursively."""
    test_dir = tmp_path / 'scan_test'
    test_dir.mkdir()
    test_file = test_dir / 'test.txt'
    test_file.write_text('This is a Testblubblah')

    matches = scan_dir(temp_compiled_rules, test_dir)

    assert len(matches) == 1
    assert 'test_string_rule' in [m.rule for m in matches]


def test_scan_dir_no_matches(temp_compiled_rules, tmp_path):
    test_dir = tmp_path / 'no_match_test'
    test_dir.mkdir()
    test_file = test_dir / 'empty.txt'
    test_file.write_text('no matching content here')

    matches = scan_dir(temp_compiled_rules, test_dir)

    assert matches == []


def test_scan_files(temp_compiled_rules, tmp_path):
    file1 = tmp_path / 'file1.txt'
    file2 = tmp_path / 'file2.txt'
    file1.write_text('This is a Testblubblah')
    file2.write_text('another Testblubblah')

    matches = scan_files(temp_compiled_rules, [str(file1), str(file2)], threads=2)

    assert len(matches) == 2
    assert 'test_string_rule' in [m.rule for m in matches]


@pytest.mark.parametrize(
    ('string_matches', 'expected'),
    [
        ([], []),
        (
            [
                StringMatch(
                    identifier='$a', instances=[StringInstance(matched_data=b'foo', offset=1337, matched_length=3)]
                )
            ],
            ['foo'],
        ),
    ],
)
def test_get_all_matched_strings(string_matches, expected):
    match = Match(rule='test_rule', meta={}, strings=string_matches, file='test_file')
    assert get_all_matched_strings([match]) == expected


def test_compile_plugin_yara_signatures(tmp_path):
    """Test compiling plugin YARA signatures."""
    plugin_dir = tmp_path / 'plugins' / 'test_plugin' / 'signatures'
    plugin_dir.mkdir(parents=True)
    (plugin_dir / 'test.yara').write_text('rule test_rule { strings: $a = "test" condition: $a }')
    output_dir = tmp_path / 'output'

    compile_plugin_yara_signatures(plugin_dir, output_dir)

    expected_output = output_dir / 'test_plugin.yc'
    assert expected_output.exists()


def test_scan_file_with_invalid_rule(tmp_path):
    invalid_rule = tmp_path / 'invalid.yara'
    invalid_rule.write_text('not a valid yara rule {')

    with pytest.raises(yara.SyntaxError):
        list(scan_file(invalid_rule, TEST_FILE))


def test_scan_file(temp_compiled_rules):
    matches = list(scan_file(temp_compiled_rules, TEST_FILE))

    assert len(matches) == 1
    assert matches[0].rule == 'test_string_rule'
