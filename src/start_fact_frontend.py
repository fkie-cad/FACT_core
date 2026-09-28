#! /usr/bin/env python3
"""
Firmware Analysis and Comparison Tool (FACT)
Copyright (C) 2015-2026  Fraunhofer FKIE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import annotations

import logging
import os
import pickle
import signal
import sys
import tempfile
from shlex import split
from subprocess import Popen, TimeoutExpired

try:
    from fact_base import FactBase
except (ImportError, ModuleNotFoundError):
    sys.exit(1)

from helperFunctions.fileSystem import get_config_dir, get_src_dir
from helperFunctions.install import run_cmd_with_logging
from web_interface.frontend_main import WebFrontEnd

COMPOSE_YAML = f'{get_src_dir()}/install/radare/docker-compose.yml'


def _is_werkzeug_reloader_child() -> bool:
    # in development mode, the werkzeug reloader runs the app in a child process that is restarted on code changes
    return os.environ.get('WERKZEUG_RUN_MAIN') == 'true'


class UwsgiServer:
    def __init__(self, config_path: str | None = None):
        self.config_path = config_path
        self.process = None

    def start(self) -> None:
        config_parameter = f' --pyargv {self.config_path}' if self.config_path else ''
        command = f'uwsgi --thunder-lock --ini  {get_config_dir()}/uwsgi_config.ini{config_parameter}'
        self.process = Popen(split(command), cwd=get_src_dir())  # noqa: S603

    def shutdown(self) -> None:
        if self.process:
            try:
                self.process.send_signal(signal.SIGINT)
                self.process.wait(timeout=30)
            except TimeoutExpired:
                logging.error('frontend did not stop in time -> kill')
                self.process.kill()


class FactFrontend(FactBase):
    PROGRAM_NAME = 'FACT Frontend'
    PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool Frontend'
    COMPONENT = 'frontend'

    def __init__(self):
        super().__init__()
        self.server = None
        if not self.args.no_radare and not _is_werkzeug_reloader_child():
            run_cmd_with_logging(f'docker compose -f {COMPOSE_YAML} up -d')

    def main(self) -> None:
        if getattr(self.args, 'development', False):
            self._run_development_server()
            return
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(pickle.dumps(self.args))
            fp.flush()
            self.server = UwsgiServer(fp.name)
            self.server.start()

            super().main()

    def _run_development_server(self) -> None:
        # the signal handlers of FactBase only set a flag and would prevent stopping the server with Ctrl+C
        signal.signal(signal.SIGINT, signal.default_int_handler)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        web_interface = WebFrontEnd(development=True)
        try:
            web_interface.app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=True)
        finally:
            if not _is_werkzeug_reloader_child():  # only clean up once in the parent process (not on every reload)
                self.shutdown()

    def shutdown(self) -> None:
        super().shutdown()
        if self.server:
            self.server.shutdown()
        if not self.args.no_radare:
            run_cmd_with_logging(f'docker compose -f {COMPOSE_YAML} down')


if __name__ == '__main__':
    FactFrontend().main()
    sys.exit(0)
