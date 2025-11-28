from base64 import b64encode
from contextlib import contextmanager

import pytest
from flask import Flask
from flask_restx import Api

from test.common_helper import create_test_file_object, create_test_firmware

from ..code.file_system_metadata import AnalysisPlugin
from ..routes import routes
from ..routes.routes import ParentAnalysisLookupMixin, _get_results_from_parent_fo


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
        self.fo.virtual_file_path[self.fw.uid] = ['/some_file']

    def get_object(self, uid):
        if uid == self.fw.uid:
            return self.fw
        if uid == self.fo.uid:
            return self.fo
        if uid == 'bar':
            fo = create_test_file_object()
            fo.parents = [self.fw.uid]
            fo.virtual_file_path = {self.fw.uid: ['/c']}
            return fo
        return None

    def get_analysis(self, uid, plugin):
        if uid == self.fw.uid and plugin == AnalysisPlugin.NAME:
            return {'result': {'files': [{'key': b64_encode('some_file'), 'mode': '1337'}]}}
        return None

    @contextmanager
    def get_read_only_session(self):
        yield None

    def get_vfps(self, uid):
        if uid == 'foo':
            return {self.fw.uid: ['/some_file']}
        return {}


class PluginRoutesMock(ParentAnalysisLookupMixin):
    def __init__(self, *_, **__):
        self.db = DbMock()


@pytest.fixture
def mock_plugin():
    return PluginRoutesMock()


class TestFileSystemMetadataRoutesStatic:
    def test_get_results_from_parent_fos(self):
        file_name = 'folder/file'
        encoded_name = b64_encode(file_name)
        parent_result = {'files': [{'key': encoded_name, 'result': 'value'}]}
        vfp = {'parent_uid': [f'/{file_name}']}

        results = _get_results_from_parent_fo(parent_result, 'parent_uid', vfp)

        assert results != {}, 'result should not be empty'
        assert file_name in results, 'files missing from result'
        assert 'parent_uid' in results[file_name], 'parent uid missing in result'
        assert 'result' in results[file_name], 'analysis result is missing'
        assert results[file_name]['result'] == 'value', 'wrong value of analysis result'

    def test_get_results_from_parent_fos__multiple_vfps_in_one_fw(self):
        file_names = ['file_a', 'file_b', 'file_c']
        vfp = {'parent_uid': [f'/{f}' for f in file_names]}
        parent_result = {'files': [{'key': b64_encode(f), 'result': 'value'} for f in file_names]}

        results = _get_results_from_parent_fo(parent_result, 'parent_uid', vfp)

        assert results is not None
        assert results != {}, 'result should not be empty'
        assert len(results) == 3, 'wrong number of results'
        assert all(f in results for f in file_names), 'files missing from result'
        assert 'result' in results[file_names[0]], 'analysis result is missing'
        assert results[file_names[0]]['result'] == 'value', 'wrong value of analysis result'

    def test_get_analysis_results_for_included_uid(self, mock_plugin):
        result = mock_plugin.get_analysis_results_for_included_uid('foo')

        assert result is not None
        assert result != [], 'result should not be empty'
        assert len(result) == 1, 'wrong number of results'
        assert 'some_file' in result[0], 'files missing from result'

    def test_get_analysis_results_for_included_uid__uid_not_found(self, mock_plugin):
        result = mock_plugin.get_analysis_results_for_included_uid('not_found')

        assert result is not None
        assert result == [], 'result should be empty'

    def test_get_analysis_results_for_included_uid__parent_not_found(self, mock_plugin):
        result = mock_plugin.get_analysis_results_for_included_uid('bar')

        assert result is not None
        assert result == [], 'result should be empty'


class DbMock:
    frontend = DbInterfaceMock()


class TestFileSystemMetadataRoutes:
    def setup_method(self):
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        for filter_ in ('replace_uid_with_hid', 'nice_unix_time', 'octal_to_readable'):
            app.jinja_env.filters[filter_] = lambda x, **_: x
        self.plugin_routes = routes.PluginRoutes(app, db=DbMock, intercom=None, status=None)
        self.test_client = app.test_client()

    def test_get_analysis_results_of_parent_fo(self):
        rv = self.test_client.get('/plugins/file_system_metadata/ajax/foo')
        assert '1337' in rv.data.decode()


class TestFileSystemMetadataRoutesRest:
    def setup_method(self):
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        api = Api(app)
        endpoint, methods = routes.PluginRestRoutes.ENDPOINTS[0]
        api.add_resource(
            routes.PluginRestRoutes,
            endpoint,
            methods=methods,
            resource_class_kwargs={'db': DbMock},
        )
        self.test_client = app.test_client()

    def test_get_rest(self):
        result = self.test_client.get('/plugins/file_system_metadata/rest/foo').json
        assert AnalysisPlugin.NAME in result
        assert 'some_file' in result[AnalysisPlugin.NAME][0]
        assert 'mode' in result[AnalysisPlugin.NAME][0]['some_file']
        assert result[AnalysisPlugin.NAME][0]['some_file']['mode'] == '1337'

    def test_get_rest__no_result(self):
        result = self.test_client.get('/plugins/file_system_metadata/rest/not_found').json
        assert result, 'result should not be empty'
        assert AnalysisPlugin.NAME in result
        assert result[AnalysisPlugin.NAME] == []
