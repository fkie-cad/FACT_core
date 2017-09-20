# -*- coding: utf-8 -*-

from common_helper_files import get_version_string_from_git, get_directory_for_filename

__VERSION__ = get_version_string_from_git(get_directory_for_filename(__file__))
