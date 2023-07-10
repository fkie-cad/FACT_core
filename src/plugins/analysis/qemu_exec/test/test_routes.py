from decorator import contextmanager
from flask import Flask
from flask_restx import Api

from test.common_helper import create_test_file_object, create_test_firmware

from ..code.qemu_exec import AnalysisPlugin
from ..routes import routes


class MockAnalysisEntry:
    def __init__(self, analysis_result=None):
        self.result = analysis_result or {}


class DbInterfaceMock:
    def __init__(self):
        self.fw = create_test_firmware()
        self.fw.uid = 'parent_uid'
        self.fw.processed_analysis[AnalysisPlugin.NAME] = {
            'files': {
                'foo': {'executable': False},
                'bar': {
                    'executable': True,
                    'path': '/some/path',
                    'results': {
                        'some-arch': {
                            '-h': {'stdout': 'stdout result', 'stderr': 'stderr result', 'return_code': '1337'}
                        }
                    },
                },
                'error-outside': {'executable': False, 'path': '/some/path', 'results': {'error': 'some error'}},
                'error-inside': {
                    'executable': False,
                    'path': '/some/path',
                    'results': {'some-arch': {'error': 'some error'}},
                },
            }
        }

        self.fo = create_test_file_object()
        self.fo.uid = 'foo'
        self.fo.parents = ['parent_uid']

    def get_object(self, uid):
        if uid == 'parent_uid':
            return self.fw
        if uid in ['foo', 'bar', 'error-outside', 'error-inside']:
            return self.fo
        return None

    def get_analysis(self, uid, plugin):
        if uid == self.fo.uid:
            return self.fo.processed_analysis.get(plugin)
        if uid == self.fw.uid:
            return self.fw.processed_analysis[AnalysisPlugin.NAME]
        return None

    def shutdown(self):
        pass

    @contextmanager
    def get_read_only_session(self):
        yield None


class TestQemuExecRoutesStatic:
    def test_get_results_for_included(self):
        result = routes.get_analysis_results_for_included_uid('foo', DbInterfaceMock())
        assert result is not None
        assert result != {}
        assert 'parent_uid' in result
        assert result['parent_uid'] == {'executable': False}

    def test_get_results_from_parent_fo(self):
        analysis_result = {'executable': False}
        result = routes._get_results_from_parent_fo({'files': {'foo': analysis_result}}, 'foo')
        assert result == analysis_result

    def test_no_results_from_parent(self):
        result = routes._get_results_from_parent_fo({}, 'foo')
        assert result is None


class DbMock:
    frontend = DbInterfaceMock()


class TestFileSystemMetadataRoutes:
    def setup(self):
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        app.jinja_env.filters['replace_uid_with_hid'] = lambda x: x
        self.plugin_routes = routes.PluginRoutes(app, db=DbMock, intercom=None)
        self.test_client = app.test_client()

    def test_not_executable(self):
        response = self.test_client.get('/plugins/qemu_exec/ajax/foo').data.decode()
        assert 'Results for this File' in response
        assert 'Executable in QEMU' in response
        assert '<td>False</td>' in response

    def test_executable(self):
        response = self.test_client.get('/plugins/qemu_exec/ajax/bar').data.decode()
        assert 'Results for this File' in response
        assert 'Executable in QEMU' in response
        assert '<td>True</td>' in response
        assert all(s in response for s in ['some-arch', 'stdout result', 'stderr result', '1337', '/some/path'])

    def test_error_outside(self):
        response = self.test_client.get('/plugins/qemu_exec/ajax/error-outside').data.decode()
        assert 'some-arch' not in response
        assert 'some error' in response

    def test_error_inside(self):
        response = self.test_client.get('/plugins/qemu_exec/ajax/error-inside').data.decode()
        assert 'some-arch' in response
        assert 'some error' in response


class TestFileSystemMetadataRoutesRest:
    def setup(self):
        app = Flask(__name__)
        app.config.from_object(__name__)
        app.config['TESTING'] = True
        api = Api(app)
        endpoint, methods = routes.QemuExecRoutesRest.ENDPOINTS[0]
        api.add_resource(
            routes.QemuExecRoutesRest,
            endpoint,
            methods=methods,
            resource_class_kwargs={'db': DbMock},
        )
        self.test_client = app.test_client()

    def test_get_rest(self):
        result = self.test_client.get('/plugins/qemu_exec/rest/foo').json
        assert AnalysisPlugin.NAME in result
        assert 'parent_uid' in result[AnalysisPlugin.NAME]
        assert result[AnalysisPlugin.NAME]['parent_uid'] == {'executable': False}

    def test_get_rest_no_result(self):
        result = self.test_client.get('/plugins/qemu_exec/rest/not_found').json
        assert AnalysisPlugin.NAME in result
        assert result[AnalysisPlugin.NAME] == {}
