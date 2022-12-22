import re
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor

import pytest

from intercom.back_end_binding import InterComBackEndBinding
from scheduler.analysis import AnalysisScheduler
from scheduler.comparison_scheduler import ComparisonScheduler
from scheduler.unpacking_scheduler import UnpackingScheduler
from storage.fsorganizer import FSOrganizer
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import get_test_data_dir
from web_interface.frontend_main import WebFrontEnd

NO_AUTH_ENDPOINTS = ['/about', '/doc', '/static', '/swagger']
REQUEST_FAILS = [b'404 Not Found', b'405 Method Not Allowed', b'The method is not allowed']
MockUser = namedtuple('MockUser', ['name', 'password', 'key'])


guest = MockUser(name='t_guest', password='test', key='1okMSKUKlYxSvPn0sgfHM0SWd9zqNChyj5fbcIJgfKM=')
guest_analyst = MockUser(name='t_guest_analyst', password='test', key='mDsgjAM2iE543PySnTpPZr0u8KeGTPGzPjKJVO4I4Ww=')
superuser = MockUser(name='t_superuser', password='test', key='k2GKnNaA5UlENStVI4AEJKQ7BP9ZqO+21Cx746BjJDo=')


@pytest.fixture
def frontend(create_tables):
    _frontend = WebFrontEnd()
    _frontend.app.config['TESTING'] = True

    yield _frontend


@pytest.fixture
def test_client(frontend):
    yield frontend.app.test_client()


@pytest.fixture
def start_backend(create_tables):
    unpacking_locks = UnpackingLockManager()

    analysis_service = AnalysisScheduler(
        post_analysis=None,
        unpacking_locks=unpacking_locks,
    )
    unpacking_service = UnpackingScheduler(
        post_unpack=analysis_service.start_analysis_of_object,
        unpacking_locks=unpacking_locks,
    )
    compare_service = ComparisonScheduler(callback=None)
    intercom = InterComBackEndBinding(
        analysis_service=analysis_service,
        compare_service=compare_service,
        unpacking_service=unpacking_service,
        unpacking_locks=unpacking_locks,
    )
    _ = FSOrganizer()

    yield

    with ThreadPoolExecutor(max_workers=4) as pool:
        pool.submit(intercom.shutdown)
        pool.submit(compare_service.shutdown)
        pool.submit(unpacking_service.shutdown)
        pool.submit(analysis_service.shutdown)


@pytest.mark.cfg_defaults(
    {
        'expert-settings': {
            'authentication': 'true',
        },
        'data-storage': {
            # Contents of user_test.db
            #
            # username,          role,          pw,    api_key
            # t_guest,           guest,         test,  1okMSKUKlYxSvPn0sgfHM0SWd9zqNChyj5fbcIJgfKM=
            # t_guest_analyst,   guest_analyst, test,  mDsgjAM2iE543PySnTpPZr0u8KeGTPGzPjKJVO4I4Ww=
            # t_superuser,       superuser,     test,  k2GKnNaA5UlENStVI4AEJKQ7BP9ZqO+21Cx746BjJDo=
            'user-database': f'sqlite:///{get_test_data_dir()}/user_test.db',
        },
    }
)
class TestAcceptanceAuthentication:
    UNIQUE_LOGIN_STRING = b'<h3 class="mx-3 mt-4">Login</h3>'
    PERMISSION_DENIED_STRING = b'You do not have permission to view this resource.'

    def test_redirection(self, test_client):
        response = test_client.get('/', follow_redirects=False)
        assert b'Redirecting' in response.data, 'no redirection taking place'

    def test_show_login_page(self, test_client):
        response = test_client.get('/', follow_redirects=True)
        assert self.UNIQUE_LOGIN_STRING in response.data, 'no authorization required'

    def test_api_key_auth(self, test_client):
        response = test_client.get('/', headers={'Authorization': guest.key}, follow_redirects=True)
        assert self.UNIQUE_LOGIN_STRING not in response.data, 'authorization not working'

    @pytest.mark.usefixtures('start_backend')
    def test_role_based_access(self, frontend, test_client):
        response = test_client.get('/upload', headers={'Authorization': guest.key}, follow_redirects=True)
        assert self.PERMISSION_DENIED_STRING in response.data, 'upload should not be accessible for guest'

        response = test_client.get('/upload', headers={'Authorization': guest_analyst.key}, follow_redirects=True)
        assert self.PERMISSION_DENIED_STRING in response.data, 'upload should not be accessible for guest_analyst'

        response = test_client.get('/upload', headers={'Authorization': superuser.key}, follow_redirects=True)
        assert self.PERMISSION_DENIED_STRING not in response.data, 'upload should be accessible for superusers'

    def test_about_doesnt_need_authentication(self, test_client):
        response = test_client.get('/about', follow_redirects=True)
        assert self.UNIQUE_LOGIN_STRING not in response.data, 'authorization required'

    @pytest.mark.skip(reason='See docstring of test_login')
    def test_login(self):
        '''
        As of now, not working in tests. Can not yet determine the reason. Maybe bad creation of request.
        Does not apply to production code though.
        Writing tests for this is postponed for now.
        '''

    def test_all_endpoints_need_authentication(self, frontend, test_client):
        fails = []
        for endpoint_rule in list(frontend.app.url_map.iter_rules()):
            # endpoints with type annotations need valid input or we get a 404
            if '<int:' in endpoint_rule.rule:
                endpoint_rule.rule = re.sub('<int:[^>]+>', '1', endpoint_rule.rule)
            endpoint = endpoint_rule.rule.replace(':', '').replace('<', '').replace('>', '')

            for method in [test_client.get, test_client.put, test_client.post]:
                response = method(endpoint, follow_redirects=True)
                if response.status_code in [405]:  # method not allowed
                    continue
                if self._endpoint_does_need_auth(endpoint) and self.UNIQUE_LOGIN_STRING not in response.data:
                    # static and about routes should be served without auth so that css and logos are shown in login
                    # screen and imprint can be accessed
                    fails.append(endpoint)
        assert fails == [], f'endpoints are missing authentication: {fails}'

    @staticmethod
    def _request_is_unsuccessful(response: bytes) -> bool:
        return any(fail in response for fail in REQUEST_FAILS)

    @staticmethod
    def _endpoint_does_need_auth(endpoint):
        return not any(endpoint.startswith(allowed_endpoint) for allowed_endpoint in NO_AUTH_ENDPOINTS)
