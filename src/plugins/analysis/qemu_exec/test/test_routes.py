# pylint: disable=protected-access,wrong-import-order,no-self-use,no-member
from unittest import TestCase

from flask import Flask
from flask_restful import Api

from test.common_helper import create_test_file_object, create_test_firmware, get_config_for_testing
from test.unit.web_interface.rest.conftest import decode_response

from ..code.qemu_exec import AnalysisPlugin
from ..routes import routes


class DbInterfaceMock:
    def __init__(self, config):
        self.config = config

        self.fw = create_test_firmware()
        self.fw.uid = 'parent_uid'
        self.fw.processed_analysis[AnalysisPlugin.NAME] = {
            'files': {
                'foo': {'executable': False},
                'bar': {
                    'executable': True, 'path': '/some/path',
                    'results': {'some-arch': {'-h': {'stdout': 'stdout result', 'stderr': 'stderr result', 'return_code': '1337'}}},
                },
                'error-outside': {'executable': False, 'path': '/some/path', 'results': {'error': 'some error'}},
                'error-inside': {
                    'executable': False, 'path': '/some/path',
                    'results': {'some-arch': {'error': 'some error'}}
                },
            }
        }

        self.fo = create_test_file_object()
        self.fo.virtual_file_path['parent_uid'] = ['parent_uid|{}|/{}'.format(self.fw.uid, 'some_file')]

    def get_object(self, uid):
        if uid == 'parent_uid':
            return self.fw
        if uid in ['foo', 'bar', 'error-outside', 'error-inside']:
            return self.fo
        return None

    def shutdown(self):
        pass


class TestQemuExecRoutesStatic(TestCase):

    def setUp(self):
        self.config = get_config_for_testing()
        routes.FrontEndDbInterface = DbInterfaceMock

    def test_get_analysis_results_for_included_uid(self):
        result = routes.get_analysis_results_for_included_uid('foo', self.config)
        assert result is not None
        assert result != {}
        assert 'parent_uid' in result
        assert result['parent_uid'] == {'executable': False}

    def test_get_parent_uids_from_virtual_path(self):
        fo = create_test_file_object()
        fo.virtual_file_path = {
            'parent1': ['parent1|foo|bar|/some_file', 'parent1|some_uid|/some_file'],
            'parent2': ['parent2|/some_file'],
        }

        result = routes._get_parent_uids_from_virtual_path(fo)
        assert len(result) == 3
        assert 'bar' in result
        assert 'some_uid' in result
        assert 'parent2' in result

    def test_get_results_from_parent_fo(self):
        parent = create_test_firmware()
        analysis_result = {'executable': False}
        parent.processed_analysis[AnalysisPlugin.NAME] = {'files': {'foo': analysis_result}}

        result = routes._get_results_from_parent_fo(parent, 'foo')
        assert result == analysis_result

    def test_get_results_from_parent_fo__no_results(self):
        parent = create_test_firmware()
        parent.processed_analysis[AnalysisPlugin.NAME] = {}

        result = routes._get_results_from_parent_fo(parent, 'foo')
        assert result is None


class TestFileSystemMetadataRoutes(TestCase):

    def setUp(self):
        routes.FrontEndDbInterface = DbInterfaceMock
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        app.jinja_env.filters['replace_uid_with_hid'] = lambda x: x
        app.jinja_env.filters['nice_unix_time'] = lambda x: x
        app.jinja_env.filters['decompress'] = lambda x: x
        config = get_config_for_testing()
        self.plugin_routes = routes.PluginRoutes(app, config)
        self.test_client = app.test_client()

    def test__get_analysis_results_not_executable(self):
        response = self.test_client.get('/plugins/qemu_exec/ajax/{}'.format('foo')).data.decode()
        assert 'Results for this File' in response
        assert 'Executable in QEMU' in response
        assert '<td>False</td>' in response

    def test__get_analysis_results_executable(self):
        response = self.test_client.get('/plugins/qemu_exec/ajax/{}'.format('bar')).data.decode()
        assert 'Results for this File' in response
        assert 'Executable in QEMU' in response
        assert '<td>True</td>' in response
        assert all(s in response for s in ['some-arch', 'stdout result', 'stderr result', '1337', '/some/path'])

    def test__get_analysis_results_with_error_outside(self):
        response = self.test_client.get('/plugins/qemu_exec/ajax/{}'.format('error-outside')).data.decode()
        assert 'some-arch' not in response
        assert 'some error' in response

    def test__get_analysis_results_with_error_inside(self):
        response = self.test_client.get('/plugins/qemu_exec/ajax/{}'.format('error-inside')).data.decode()
        assert 'some-arch' in response
        assert 'some error' in response


class TestFileSystemMetadataRoutesRest(TestCase):

    def setUp(self):
        routes.FrontEndDbInterface = DbInterfaceMock
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        config = get_config_for_testing()
        api = Api(app)
        endpoint, methods = routes.QemuExecRoutesRest.ENDPOINTS[0]
        api.add_resource(
            routes.QemuExecRoutesRest,
            endpoint,
            methods=methods,
            resource_class_kwargs={'config': config}
        )
        self.test_client = app.test_client()

    def test__get_rest(self):
        result = decode_response(self.test_client.get('/plugins/qemu_exec/rest/{}'.format('foo')))
        assert AnalysisPlugin.NAME in result
        assert 'parent_uid' in result[AnalysisPlugin.NAME]
        assert result[AnalysisPlugin.NAME]['parent_uid'] == {'executable': False}

    def test__get_rest__no_result(self):
        result = decode_response(self.test_client.get('/plugins/qemu_exec/rest/{}'.format('not_found')))
        assert AnalysisPlugin.NAME in result
        assert result[AnalysisPlugin.NAME] == {}
