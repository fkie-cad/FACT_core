import os

from test.acceptance.base import TestAcceptanceBase
from helperFunctions.fileSystem import get_test_data_dir


class TestAuthenticatedAcceptanceBase(TestAcceptanceBase):
    '''
    Contents of user_test.db

    username,           role,           pw,     api_key
    t_guest,            guest,          test,   1okMSKUKlYxSvPn0sgfHM0SWd9zqNChyj5fbcIJgfKM=
    t_guest_analyst,    guest_analyst,  test,   mDsgjAM2iE543PySnTpPZr0u8KeGTPGzPjKJVO4I4Ww=
    t_superuser,        superuser,      test,   k2GKnNaA5UlENStVI4AEJKQ7BP9ZqO+21Cx746BjJDo=
    '''
    @classmethod
    def _set_config(cls):
        super()._set_config()
        cls.config.set('ExpertSettings', 'authentication', 'true')
        cls.config.set('data_storage', 'user_database', os.path.join(get_test_data_dir(), 'user_test.db'))
