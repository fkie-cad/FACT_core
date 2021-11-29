import json
import subprocess
from pathlib import Path
from subprocess import PIPE

CONFIG_FILE_PATH = Path(__file__).parent / 'config/eslintrc.js'


class JavaScriptLinter:
    '''
    Wrapper for eslint javascript linter
    '''

    def do_analysis(self, file_path):
        # The linter will have nonzero returncode when a rule matches
        # pylint: disable=subprocess-run-check
        output_raw = subprocess.run(
                    f'''docker run
                        --rm
                        -v {CONFIG_FILE_PATH}:/eslintrc.js
                        -v {file_path}:/input.js
                        cytopia/eslint
                        -c /eslintrc.js
                        --format json
                        /input.js'''.split(),
                    stdout=PIPE, stderr=PIPE).stdout

        output_json = json.loads(output_raw)

        issues = []
        # As we only ever analyse one file use output_json[0]
        for msg in output_json[0]['messages']:
            issues.append(dict(line=msg['line'], column=msg['column'], message=msg['message'], symbol=msg['ruleId']))

        return issues
