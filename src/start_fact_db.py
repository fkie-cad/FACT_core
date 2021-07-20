#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2021  Fraunhofer FKIE

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
'''

import sys

from fact_base import FactBase

from helperFunctions.program_setup import program_setup
from storage.MongoMgr import MongoMgr


class FactDb(FactBase):
    PROGRAM_NAME = 'FACT DB-Service'
    PROGRAM_DESCRIPTION = 'Firmware Analysis and Compare Tool (FACT) DB-Service'
    COMPONENT = 'database'

    def __init__(self):
        _, config = program_setup(self.PROGRAM_NAME, self.PROGRAM_DESCRIPTION, self.COMPONENT)
        self.mongo_server = MongoMgr(config=config)
        super().__init__()

    def shutdown(self):
        super().shutdown()
        self.mongo_server.shutdown()


if __name__ == '__main__':
    FactDb().main()
    sys.exit()
