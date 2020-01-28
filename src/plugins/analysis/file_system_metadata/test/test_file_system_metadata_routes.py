# pylint: disable=invalid-name
from base64 import b64encode
from unittest import TestCase

from flask import Flask
from flask_restful import Api

from helperFunctions.database import ConnectTo
from test.common_helper import create_test_file_object, create_test_firmware, get_config_for_testing
from test.unit.web_interface.rest.conftest import decode_response

from ..code.file_system_metadata import AnalysisPlugin
from ..routes import routes


class DbInterfaceMock:
    def __init__(self, config):
        self.config = config
        self.fw = create_test_firmware()
        self.fw.processed_analysis[AnalysisPlugin.NAME] = {'files': {b64_encode('some_file'): {'test_result': 'test_value'}}}
        self.fo = create_test_file_object()
        self.fo.virtual_file_path['some_uid'] = ['some_uid|{}|/{}'.format(self.fw.uid, 'some_file')]

    def get_object(self, uid):
        if uid == self.fw.uid:
            return self.fw
        if uid == 'foo':
            return self.fo
        if uid == 'bar':
            fo = create_test_file_object()
            fo.virtual_file_path = {'some_uid': ['a|b|c']}
            return fo
        return None

    def shutdown(self):
        pass


class TestFileSystemMetadataRoutesStatic(TestCase):

    def setUp(self):
        self.config = get_config_for_testing()
        routes.FsMetadataDbInterface.__bases__ = (DbInterfaceMock,)

    def test_get_results_from_parent_fos(self):
        fw = create_test_firmware()
        fo = create_test_file_object()
        file_name = 'folder/file'
        encoded_name = b64_encode(file_name)

        fw.processed_analysis[AnalysisPlugin.NAME] = {'files': {encoded_name: {'result': 'value'}}}
        fo.virtual_file_path['some_uid'] = ['some_uid|{}|/{}'.format(fw.uid, file_name)]

        results = {}
        routes.FsMetadataRoutesDbInterface.get_results_from_parent_fos(fw, fo, results)

        assert results != {}, 'result should not be empty'
        assert file_name in results, 'files missing from result'
        assert 'parent_uid' in results[file_name], 'parent uid missing in result'
        assert 'result' in results[file_name], 'analysis result is missing'
        assert results[file_name]['result'] == 'value', 'wrong value of analysis result'

    def test_get_results_from_parent_fos__multiple_vfps_in_one_fw(self):
        fw = create_test_firmware()
        fo = create_test_file_object()
        file_names = ['file_a', 'file_b', 'file_c']

        fw.processed_analysis[AnalysisPlugin.NAME] = {'files': {b64_encode(f): {'result': 'value'} for f in file_names}}

        vfp = fo.virtual_file_path['some_uid'] = []
        for f in file_names:
            vfp.append('some_uid|{}|/{}'.format(fw.uid, f))

        results = {}
        routes.FsMetadataRoutesDbInterface.get_results_from_parent_fos(fw, fo, results)

        assert results is not None
        assert results != {}, 'result should not be empty'
        assert len(results) == 3, 'wrong number of results'
        assert all(f in results for f in file_names), 'files missing from result'
        assert 'result' in results[file_names[0]], 'analysis result is missing'
        assert results[file_names[0]]['result'] == 'value', 'wrong value of analysis result'

    def test_get_analysis_results_for_included_uid(self):
        with ConnectTo(routes.FsMetadataRoutesDbInterface, self.config) as db_interface:
            result = db_interface.get_analysis_results_for_included_uid('foo')

        assert result is not None
        assert result != {}, 'result should not be empty'
        assert len(result) == 1, 'wrong number of results'
        assert 'some_file' in result, 'files missing from result'

    def test_get_analysis_results_for_included_uid__uid_not_found(self):
        with ConnectTo(routes.FsMetadataRoutesDbInterface, self.config) as db_interface:
            result = db_interface.get_analysis_results_for_included_uid('not_found')

        assert result is not None
        assert result == {}, 'result should be empty'

    def test_get_analysis_results_for_included_uid__parent_not_found(self):
        with ConnectTo(routes.FsMetadataRoutesDbInterface, self.config) as db_interface:
            result = db_interface.get_analysis_results_for_included_uid('bar')

        assert result is not None
        assert result == {}, 'result should be empty'


class TestFileSystemMetadataRoutes(TestCase):

    def setUp(self):
        routes.FrontEndDbInterface = DbInterfaceMock
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        app.jinja_env.filters['replace_uid_with_hid'] = lambda x: x
        app.jinja_env.filters['nice_unix_time'] = lambda x: x
        config = get_config_for_testing()
        self.plugin_routes = routes.PluginRoutes(app, config)
        self.test_client = app.test_client()

    def test_get_analysis_results_of_parent_fo(self):
        rv = self.test_client.get('/plugins/file_system_metadata/ajax/{}'.format('foo'))
        assert 'test_result' in rv.data.decode()
        assert 'test_value' in rv.data.decode()


class TestFileSystemMetadataRoutesRest(TestCase):

    def setUp(self):
        routes.FrontEndDbInterface = DbInterfaceMock
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        config = get_config_for_testing()
        api = Api(app)
        endpoint, methods = routes.FSMetadataRoutesRest.ENDPOINTS[0]
        api.add_resource(
            routes.FSMetadataRoutesRest,
            endpoint,
            methods=methods,
            resource_class_kwargs={'config': config}
        )
        self.test_client = app.test_client()

    def test_get_rest(self):
        result = decode_response(self.test_client.get('/plugins/file_system_metadata/rest/{}'.format('foo')))
        assert AnalysisPlugin.NAME in result
        assert 'some_file' in result[AnalysisPlugin.NAME]
        assert 'test_result' in result[AnalysisPlugin.NAME]['some_file']

    def test_get_rest__no_result(self):
        result = decode_response(self.test_client.get('/plugins/file_system_metadata/rest/{}'.format('not_found')))
        assert AnalysisPlugin.NAME in result
        assert result[AnalysisPlugin.NAME] == {}


def b64_encode(string):
    return b64encode(string.encode()).decode()
