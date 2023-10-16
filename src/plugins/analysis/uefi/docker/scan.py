#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
import yaml
from pathlib import Path
from shlex import split
from subprocess import run

RULE_SUFFIXES = ['.yml', '.yaml']
RULES = Path(__file__).parent / 'rules'
INPUT_FILE = Path('/input/file')
OUTPUT_FILE = Path('/output/file')
BLACKLIST = [
    'RsbStuffingCheck.yml',  # too many false positives
]
CLI_COLOR_REGEX = re.compile(rb'\x1b\[\d{1,3}m')
RESULT_PARSING_REGEX = re.compile(r'Scanner result ([^\n]+?) \(variant: ([^\n]+?)\) ([^(]+?)(?: \(|\n|$)')
NO_MATCH_STR = 'No threat detected'


def main():
    _validate_setup()
    rule_files = _find_rule_files()
    _scan_file(_load_rules(rule_files), rule_files)


def _validate_setup():
    if not INPUT_FILE.is_file():
        print('error: input file not found')
        sys.exit(1)
    if not RULES.is_dir():
        print('error: rules dir not found')
        sys.exit(2)


def _find_rule_files() -> list[Path]:
    return [file for file in RULES.glob('**/*') if _is_rule_file(file) and file.name not in BLACKLIST]


def _load_rules(rule_files: list[Path]) -> dict[str, dict]:
    """
    Rule structure should look something like this:
    {
      "<rule_name>": {
        "meta": {
          "author": "...",
          "name": "...",
          "namespace": "<rule_type>",
          "description": "...",
          "url": "...",
          ...
        },
        "variants": {
          "<variant_name>": {
            "<requirement>": {...}
          },
          ...
        }
      }
    }
    """
    rules = {}
    for file in rule_files:
        with file.open('rb') as fp:
            rule_data = yaml.safe_load(fp)
            for rule_dict in rule_data.values():
                rules[rule_dict['meta']['name']] = rule_dict
    return rules


def _scan_file(rules: dict[str, dict], rule_files: list[Path]):
    rules_str = ' '.join(f'-r {file}' for file in rule_files)
    mode = os.environ.get('UEFI_ANALYSIS_MODE', default='module')
    proc = run(
        split(f'fwhunt_scan_analyzer.py scan-{mode} {INPUT_FILE} {rules_str}'),
        capture_output=True,
    )
    if proc.returncode != 0:
        print(f'warning: Scan exited with return code {proc.returncode}: {proc.stderr}')
    else:
        output = CLI_COLOR_REGEX.sub(b'', proc.stdout).decode(errors='replace')
        result = _parse_output(output, rules)
        OUTPUT_FILE.write_text(json.dumps(result))


def _parse_output(output: str, rules: dict[str, dict]) -> dict[str, dict]:
    result = {}
    for rule_name, variant, detected in RESULT_PARSING_REGEX.findall(output):
        rule_data = rules.get(rule_name)
        if rule_data is None:
            print(f'error: rule {rule_name} not found')
            sys.exit(3)
        result.setdefault(
            rule_name,
            {
                'category': rule_data['meta']['namespace'],
                'description': rule_data['meta'].get('description'),
                'author': rule_data['meta'].get('author'),
                'url': rule_data['meta'].get('url'),
                'variants': {},
            },
        )
        result[rule_name]['variants'][variant] = {
            'output': detected,
            'match': NO_MATCH_STR not in detected,
        }
    return result


def _is_rule_file(rule: Path) -> bool:
    return rule.is_file() and rule.suffix in RULE_SUFFIXES


if __name__ == '__main__':
    main()
