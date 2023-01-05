# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Path setup --------------------------------------------------------------

import sys
from pathlib import Path

FACT_SRC = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(FACT_SRC))


# -- Project information -----------------------------------------------------

# pylint: disable=redefined-builtin,invalid-name
project = 'FACT'
copyright = '2020-2022  Fraunhofer FKIE'
author = 'jstucke'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.autodoc',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = 'sphinx_rtd_theme'
# html_theme = 'alabaster'

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

html_logo = '../src/web_interface/static/FACT_smaller.png'

# This value contains a list of modules to be mocked up. This is useful when some external dependencies
# are not met at build time and break the building process. You may only specify the root package
autodoc_mock_imports = [
    'common_helper_encoder',
    'common_helper_files',
    'common_helper_mongo',
    'distro',
    'docker',
    'flask',
    'gridfs',
    'lief',
    'matplotlib',
    'numpy',
    'passlib',
    'pluginbase',
    'psutil',
    'pydantic',
    'pymongo',
    'pytest',
    'requests',
    'si_prefix',
    'sqlalchemy',
    'ssdeep',
    'tlsh',
    'werkzeug',
    'yaml',
    'yara',
]

# This value controls how to represent typehints. The setting takes the following values:
#     'signature' – Show typehints as its signature (default)
#     'description' – Show typehints as content of function or method
#     'none' – Do not show typehints
autodoc_typehints = 'description'


def setup(app):
    app.add_css_file('css/custom.css')
