from pathlib import Path

import pytest

from web_interface.components.dependency_graph import DepGraphData
from web_interface.components.file_reference_graph import (
    _find_probable_home_dir,
    get_edges_and_nodes,
    resolve_relative_path,
)


def test_get_edges_and_nodes():
    data_by_path = {
        '/foo/bar': DepGraphData('uid1', 'bar', ['/foo/bar'], 'text/plain', 'text file', ['/test/1234']),
        '/test/1234': DepGraphData('uid2', '1234', ['/test/1234'], 'text/plain', 'text file', []),
    }
    edges, nodes = get_edges_and_nodes(data_by_path)
    assert nodes == {'/foo/bar', '/test/1234'}
    assert edges == {('/foo/bar', '/test/1234')}


def test_filter_lib():
    data_by_path = {
        '/bin/foo': DepGraphData(
            'uid1', 'foo', ['/bin/foo'], 'application/x-executable', 'some ELF file', ['/lib/bar']
        ),
        '/lib/bar': DepGraphData('uid2', 'bar', ['/lib/bar'], 'application/x-sharedlib', 'some ELF lib', []),
    }
    edges, nodes = get_edges_and_nodes(data_by_path)
    assert nodes == set(), 'should have been filtered out'
    assert edges == set()


@pytest.mark.parametrize(
    ('source', 'target', 'expected'),
    [
        ('/foo/bar', '/foo/bar', '/foo/bar'),
        ('/foo/bar', './baz', '/foo/baz'),
        ('/foo/bar', '../baz', '/baz'),
        ('/foo/bar/test', '../../baz', '/baz'),
        ('/foo/bar/test', '/foo/bar/../baz', '/foo/baz'),
        ('/foo/bar', '~/baz', '/home/foo/baz'),
    ],
)
def test_resolve_relative_path(source, target, expected):
    assert resolve_relative_path(source, target, Path('/home/foo')) == expected


def test_find_probable_home_dir():
    assert _find_probable_home_dir(['/home/foo/bar']) == Path('/home/foo')
    assert _find_probable_home_dir(['/foo/bar']) == Path('/root')
