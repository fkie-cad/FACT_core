import json
import logging
import subprocess
from pathlib import Path
from subprocess import PIPE, STDOUT
from typing import List, Tuple

from docker.types import Mount

from helperFunctions.docker import run_docker_container


def run_eslint(file_path):
    eslintrc_path = Path(__file__).parent / 'config/eslintrc.js'

    result = run_docker_container(
        'cytopia/eslint',
        combine_stderr_stdout=False,
        mounts=[
            Mount('/eslintrc.js', str(eslintrc_path), type='bind', read_only=True),
            Mount('/input.js', str(file_path), type='bind', read_only=True),
        ],
        command='-c /eslintrc.js --format json /input.js',
    )

    output_json = json.loads(result.stdout)

    issues = []
    # As we only ever analyse one file use output_json[0]
    for msg in output_json[0]['messages']:
        issues.append(dict(line=msg['line'], column=msg['column'], message=msg['message'], symbol=msg['ruleId']))

    return issues


def run_shellcheck(file_path):
    shellcheck_process = subprocess.run(
        f'shellcheck --format=json {file_path}',
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        check=False,
        universal_newlines=True,
    )

    if shellcheck_process.returncode == 2:
        logging.debug(f'Failed to execute shellcheck:\n{shellcheck_process.stdout}')
        return []

    try:
        shellcheck_json = json.loads(shellcheck_process.stdout)
    except json.JSONDecodeError:
        return []

    return _extract_shellcheck_warnings(shellcheck_json)


def _extract_shellcheck_warnings(shellcheck_json):
    issues = []
    for issue in shellcheck_json:
        if issue['level'] in ['warning', 'error']:
            issues.append({
                'type': issue['level'],
                'line': issue['line'],
                'column': issue['column'],
                'symbol': str(issue['code']),
                'message': issue['message'],
            })
    return issues


def run_luacheck(file_path):
    luacheckrc_path = Path(Path(__file__).parent, 'config', 'luacheckrc')

    luacheck_process = subprocess.run(
        f'luacheck -q --ranges --config  {luacheckrc_path} {file_path}',
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        check=False,
        universal_newlines=True,
    )
    return _luacheck_parse_linter_output(luacheck_process.stdout)


def _luacheck_parse_linter_output(output):
    '''
    https://luacheck.readthedocs.io/en/stable/warnings.html
    ignore_cases = ['(W611)', '(W612)', '(W613)', '(W614)', '(W621)', '(W631)']
    '''
    issues = []
    for line in output.splitlines():
        try:
            line_number, columns, code_and_message = _luacheck_split_issue_line(line)
            code, message = _separate_message_and_code(code_and_message)
            if not code.startswith('(W6'):
                issues.append({
                    'line': int(line_number),
                    'column': _luacheck_get_first_column(columns),
                    'symbol': code,
                    'message': message,
                })
            else:
                pass
        except (IndexError, ValueError) as error:
            logging.warning(f'Lualinter failed to parse line: {line}\n{error}')

    return issues


def _luacheck_split_issue_line(line):
    split_by_colon = line.split(':')
    return split_by_colon[1], split_by_colon[2], ':'.join(split_by_colon[3:]).strip()


def _separate_message_and_code(message_string: str) -> Tuple[str, str]:
    return message_string[1:5], message_string[6:].strip()


def _luacheck_get_first_column(columns):
    return int(columns.split('-')[0])


def run_pylint(file_path):
    pylint_process = subprocess.run(
        f'pylint --output-format=json {file_path}',
        shell=True,
        stdout=PIPE,
        stderr=STDOUT,
        check=False,
        universal_newlines=True
    )

    try:
        pylint_json = json.loads(pylint_process.stdout)
    except json.JSONDecodeError:
        logging.warning(f'Failed to execute pylint:\n{pylint_process.stdout}')
        return []

    return _pylint_extract_relevant_warnings(pylint_json)


def _pylint_extract_relevant_warnings(pylint_json):
    issues = []
    for issue in pylint_json:
        if issue['type'] in ['error', 'warning']:
            for unnecessary_information in ['module', 'obj', 'path', 'message-id']:
                issue.pop(unnecessary_information)
            issues.append(issue)
    return issues


def run_rubocop(file_path: str) -> List[dict]:
    container_path = '/input'
    process = run_docker_container(
        'pipelinecomponents/rubocop:latest',
        combine_stderr_stdout=False,
        mounts=[
            Mount(container_path, file_path, type='bind', read_only=True),
        ],
        command=f'rubocop --format json -- {container_path}',
    )

    try:
        linter_output = json.loads(process.stdout)
    except json.JSONDecodeError:
        logging.warning(f'Failed to execute rubocop linter:\n{process.stderr}')
        return []

    return [
        {
            'symbol': offense['cop_name'],
            'line': offense['location']['start_line'],
            'column': offense['location']['column'],
            'message': offense['message'],
        }
        for offense in linter_output['files'][0]['offenses']
    ]


def run_phpstan(file_path):
    container_path = '/app/input.php'
    phpstan_p = run_docker_container(
        'ghcr.io/phpstan/phpstan',
        combine_stderr_stdout=False,
        mounts=[
            Mount(container_path, file_path, type='bind', read_only=True),
        ],
        command='analyse --error-format=json -- input.php',
    )

    linter_output = json.loads(phpstan_p.stdout)

    issues = []
    for message in linter_output['files'][container_path]['messages']:
        issues.append(
            {
                'symbol': 'error',  # phpstan errors do not have codes or names
                'line': message['line'],
                'column': -1,  # phpstan does not report columns
                'message': message['message'],
            }
        )

    return issues
