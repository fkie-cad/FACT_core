from collections import namedtuple

from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_test_data_dir

MockUser = namedtuple('MockUser', ['name', 'password', 'key'])


class TestAuthenticatedAcceptanceBase(TestAcceptanceBase):
    '''
    Contents of user_test.db

    username,          role,          pw,    api_key
    t_guest,           guest,         test,  1okMSKUKlYxSvPn0sgfHM0SWd9zqNChyj5fbcIJgfKM=
    t_guest_analyst,   guest_analyst, test,  mDsgjAM2iE543PySnTpPZr0u8KeGTPGzPjKJVO4I4Ww=
    t_superuser,       superuser,     test,  k2GKnNaA5UlENStVI4AEJKQ7BP9ZqO+21Cx746BjJDo=
    '''

    @classmethod
    def _set_config(cls):
        super()._set_config()
        cls.config.set('expert-settings', 'authentication', 'true')
        cls.config.set('data-storage', 'user-database', ''.join(['sqlite:///', get_test_data_dir(), '/user_test.db']))

        cls.guest = MockUser(name='t_guest', password='test', key='1okMSKUKlYxSvPn0sgfHM0SWd9zqNChyj5fbcIJgfKM=')
        cls.guest_analyst = MockUser(
            name='t_guest_analyst', password='test', key='mDsgjAM2iE543PySnTpPZr0u8KeGTPGzPjKJVO4I4Ww='
        )
        cls.superuser = MockUser(
            name='t_superuser', password='test', key='k2GKnNaA5UlENStVI4AEJKQ7BP9ZqO+21Cx746BjJDo='
        )
