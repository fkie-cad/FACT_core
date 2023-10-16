#! /usr/bin/env python3  # noqa: EXE001
"""
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2023  Fraunhofer FKIE

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

import pickle
import sys
from pathlib import Path

import config
from helperFunctions.program_setup import setup_logging
from web_interface.frontend_main import WebFrontEnd


def create_web_interface():
    args_path = Path(sys.argv[-1])
    args = None
    if args_path.is_file():
        args = pickle.loads(args_path.read_bytes())
        config_file = getattr(args, 'config_file', None)
        config.load(config_file)

    setup_logging(args, 'frontend')
    return WebFrontEnd()


web_interface = create_web_interface()
app = web_interface.app
