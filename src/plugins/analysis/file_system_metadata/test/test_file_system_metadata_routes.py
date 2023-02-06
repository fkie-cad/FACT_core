# pylint: disable=invalid-name,no-self-use,use-implicit-booleaness-not-comparison,attribute-defined-outside-init,wrong-import-order
from base64 import b64encode
from unittest import TestCase

from decorator import contextmanager
from flask import Flask
from flask_restx import Api

from test.common_helper import create_test_file_object, create_test_firmware

from ..code.file_system_metadata import AnalysisPlugin
from ..routes import routes
from ..routes.routes import _get_results_from_parent_fo


def b64_encode(string):
    return b64encode(string.encode()).decode()


class DbInterfaceMock:
    def __init__(self):
        self.fw = create_test_firmware()
        self.fw.processed_analysis[AnalysisPlugin.NAME] = {
            'files': {b64_encode('some_file'): {'test_result': 'test_value'}}
        }
        self.fo = create_test_file_object()
        self.fo.uid = 'foo'
        self.fo.parents = [self.fw.uid]
        self.fo.virtual_file_path['some_uid'] = [f'some_uid|{self.fw.uid}|/some_file']

    def get_object(self, uid):
        if uid == self.fw.uid:
            return self.fw
        if uid == self.fo.uid:
            return self.fo
        if uid == 'bar':
            fo = create_test_file_object()
            fo.parents = [self.fw.uid]
            fo.virtual_file_path = {'some_uid': ['a|b|c']}
            return fo
        return None

    def get_analysis(self, uid, plugin):
        if uid == self.fw.uid and plugin == AnalysisPlugin.NAME:
            return {'files': {b64_encode('some_file'): {'test_result': 'test_value'}}}
        return None

    @contextmanager
    def get_read_only_session(self):
        yield None


class TestFileSystemMetadataRoutesStatic:
    def test_get_results_from_parent_fos(self):
        fo = create_test_file_object()
        file_name = 'folder/file'
        encoded_name = b64_encode(file_name)
        parent_result = {'files': {encoded_name: {'result': 'value'}}}
        fo.virtual_file_path['some_uid'] = [f'some_uid|parent_uid|/{file_name}']

        results = _get_results_from_parent_fo(parent_result, 'parent_uid', fo)

        assert results != {}, 'result should not be empty'
        assert file_name in results, 'files missing from result'
        assert 'parent_uid' in results[file_name], 'parent uid missing in result'
        assert 'result' in results[file_name], 'analysis result is missing'
        assert results[file_name]['result'] == 'value', 'wrong value of analysis result'

    def test_get_results_from_parent_fos__multiple_vfps_in_one_fw(self):
        fo = create_test_file_object()
        fo.parents = ['parent_uid']
        file_names = ['file_a', 'file_b', 'file_c']
        fo.virtual_file_path['some_uid'] = [f'some_uid|parent_uid|/{f}' for f in file_names]
        parent_result = {'files': {b64_encode(f): {'result': 'value'} for f in file_names}}

        results = _get_results_from_parent_fo(parent_result, 'parent_uid', fo)

        assert results is not None
        assert results != {}, 'result should not be empty'
        assert len(results) == 3, 'wrong number of results'
        assert all(f in results for f in file_names), 'files missing from result'
        assert 'result' in results[file_names[0]], 'analysis result is missing'
        assert results[file_names[0]]['result'] == 'value', 'wrong value of analysis result'

    def test_get_analysis_results_for_included_uid(self):
        result = routes.get_analysis_results_for_included_uid('foo', DbInterfaceMock())

        assert result is not None
        assert result != {}, 'result should not be empty'
        assert len(result) == 1, 'wrong number of results'
        assert 'some_file' in result, 'files missing from result'

    def test_get_analysis_results_for_included_uid__uid_not_found(self):
        result = routes.get_analysis_results_for_included_uid('not_found', DbInterfaceMock())

        assert result is not None
        assert result == {}, 'result should be empty'

    def test_get_analysis_results_for_included_uid__parent_not_found(self):
        result = routes.get_analysis_results_for_included_uid('bar', DbInterfaceMock())

        assert result is not None
        assert result == {}, 'result should be empty'


class DbMock:
    frontend = DbInterfaceMock()


class TestFileSystemMetadataRoutes:
    def setup(self):
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        app.jinja_env.filters['replace_uid_with_hid'] = lambda x: x  # pylint: disable=no-member
        self.plugin_routes = routes.PluginRoutes(app, db=DbMock, intercom=None)
        self.test_client = app.test_client()

    def test_get_analysis_results_of_parent_fo(self):
        rv = self.test_client.get('/plugins/file_system_metadata/ajax/foo')
        assert 'test_result' in rv.data.decode()
        assert 'test_value' in rv.data.decode()


class TestFileSystemMetadataRoutesRest(TestCase):
    def setUp(self):
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        api = Api(app)
        endpoint, methods = routes.FSMetadataRoutesRest.ENDPOINTS[0]
        api.add_resource(
            routes.FSMetadataRoutesRest,
            endpoint,
            methods=methods,
            resource_class_kwargs={'db': DbMock},
        )
        self.test_client = app.test_client()

    def test_get_rest(self):
        result = self.test_client.get('/plugins/file_system_metadata/rest/foo').json
        assert AnalysisPlugin.NAME in result
        assert 'some_file' in result[AnalysisPlugin.NAME]
        assert 'test_result' in result[AnalysisPlugin.NAME]['some_file']

    def test_get_rest__no_result(self):
        result = self.test_client.get('/plugins/file_system_metadata/rest/not_found').json
        assert AnalysisPlugin.NAME in result
        assert result[AnalysisPlugin.NAME] == {}
