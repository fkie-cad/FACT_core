# -*- coding: utf-8 -*-
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2017  Fraunhofer FKIE

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

from common_helper_files import get_version_string_from_git, get_directory_for_filename

__VERSION__ = get_version_string_from_git(get_directory_for_filename(__file__))
