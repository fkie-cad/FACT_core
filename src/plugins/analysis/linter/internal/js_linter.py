import json
from pathlib import Path

from docker.types import Mount

from helperFunctions.docker import run_docker_container

CONFIG_FILE_PATH = Path(__file__).parent / 'config/eslintrc.js'


class JavaScriptLinter:
    '''
    Wrapper for eslint javascript linter
    '''

    def do_analysis(self, file_path):
        output_raw, _ = run_docker_container(
            'cytopia/eslint',
            mounts=[
                Mount('/eslintrc.js', str(CONFIG_FILE_PATH), type='bind', read_only=True),
                Mount('/input.js', str(file_path), type='bind', read_only=True),
            ],
            command='-c /eslintrc.js --format json /input.js',
        )

        output_json = json.loads(output_raw)

        issues = []
        # As we only ever analyse one file use output_json[0]
        for msg in output_json[0]['messages']:
            issues.append(dict(line=msg['line'], column=msg['column'], message=msg['message'], symbol=msg['ruleId']))

        return issues
