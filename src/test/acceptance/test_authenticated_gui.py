import re

import pytest

from test.acceptance.auth_base import TestAuthenticatedAcceptanceBase

NO_AUTH_ENDPOINTS = ['/about', '/doc', '/static', '/swagger']
REQUEST_FAILS = [b'404 Not Found', b'405 Method Not Allowed', b'The method is not allowed']


class TestAcceptanceAuthentication(TestAuthenticatedAcceptanceBase):
    UNIQUE_LOGIN_STRING = b'<h3 class="mx-3 mt-4">Login</h3>'
    PERMISSION_DENIED_STRING = b'You do not have permission to view this resource.'

    @pytest.mark.skip(reason='TODO')
    def test_redirection(self):
        response = self.test_client.get('/', follow_redirects=False)
        self.assertIn(b'Redirecting', response.data, 'no redirection taking place')

    @pytest.mark.skip(reason='TODO')
    def test_show_login_page(self):
        response = self.test_client.get('/', follow_redirects=True)
        self.assertIn(self.UNIQUE_LOGIN_STRING, response.data, 'no authorization required')

    def test_api_key_auth(self):
        response = self.test_client.get('/', headers={'Authorization': self.guest.key}, follow_redirects=True)
        self.assertNotIn(self.UNIQUE_LOGIN_STRING, response.data, 'authorization not working')

    @pytest.mark.skip(reason='TODO')
    def test_role_based_access(self):
        self._start_backend()
        try:
            response = self.test_client.get('/upload', headers={'Authorization': self.guest.key}, follow_redirects=True)
            self.assertIn(self.PERMISSION_DENIED_STRING, response.data, 'upload should not be accessible for guest')

            response = self.test_client.get(
                '/upload', headers={'Authorization': self.guest_analyst.key}, follow_redirects=True
            )
            self.assertIn(
                self.PERMISSION_DENIED_STRING, response.data, 'upload should not be accessible for guest_analyst'
            )

            response = self.test_client.get(
                '/upload', headers={'Authorization': self.superuser.key}, follow_redirects=True
            )
            self.assertNotIn(self.PERMISSION_DENIED_STRING, response.data, 'upload should be accessible for superusers')
        finally:
            self._stop_backend()

    def test_about_doesnt_need_authentication(self):
        response = self.test_client.get('/about', follow_redirects=True)
        self.assertNotIn(self.UNIQUE_LOGIN_STRING, response.data, 'authorization required')

    def test_login(self):
        '''
        As of now, not working in tests. Can not yet determine the reason. Maybe bad creation of request.
        Does not apply to production code though.
        Writing tests for this is postponed for now.
        '''
        pass  # pylint: disable=unnecessary-pass

    # TODO remove this
    @pytest.mark.skip(reason='Takes way too long')
    def test_all_endpoints_need_authentication(self):
        fails = []
        for endpoint_rule in list(self.frontend.app.url_map.iter_rules()):
            # endpoints with type annotations need valid input or we get a 404
            if '<int:' in endpoint_rule.rule:
                endpoint_rule.rule = re.sub('<int:[^>]+>', '1', endpoint_rule.rule)
            endpoint = endpoint_rule.rule.replace(':', '').replace('<', '').replace('>', '')

            for method in [self.test_client.get, self.test_client.put, self.test_client.post]:
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
