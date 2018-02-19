import os
from collections import namedtuple

from test.acceptance.base import TestAcceptanceBase
from helperFunctions.fileSystem import get_test_data_dir

ALL_ENDPOINTS_2018_02_19 = ['/database/database_binary_search_results.html',  '/database/advanced_search',  '/database/browse_compare',  '/database/binary_search',  '/database/quick_search',  '/database/browse',  '/database/search',  '/rest/file_object',  '/rest/firmware',  '/rest/compare',  '/rest/file_object/<uid>',  '/rest/firmware/<uid>',  '/rest/compare/<compare_id>',  '/rest/binary/<uid>',  '/system_health',  '/statistic',  '/compare',  '/upload',  '/about',  '/',  '/comparison/remove_all/<analysis_uid>',  '/comparison/remove/<analysis_uid>/<compare_uid>',  '/comparison/add/<uid>',  '/analysis/<uid>/ro/<root_uid>',  '/analysis/<uid>/<selected_analysis>/ro/<root_uid>',  '/compare/ajax_common_files/<compare_id>/<feature_id>/',  '/compare/ajax_tree/<compare_id>/<root_uid>/<uid>',  '/admin/delete_comment/<uid>/<timestamp>',  '/admin/re-do_analysis/<uid>',  '/admin/delete/<uid>',  '/base64-download/<uid>/<section>/<expression_id>',  '/ajax_get_binary/<mime_type>/<uid>',  '/update-analysis/<uid>',  '/tar-download/<uid>',  '/ida-download/<compare_id>',  '/ajax_tree/<uid>/<root_uid>',  '/ajax_root/<uid>',  '/analysis/<uid>/<selected_analysis>',  '/analysis/<uid>',  '/download/<uid>',  '/hex-dump/<uid>',  '/compare/<compare_id>',  '/comment/<uid>',  '/static/<filename>']
MockUser = namedtuple('MockUser', ['name', 'password', 'key'])

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
        cls.config.set('data_storage', 'user_database', ''.join(['sqlite:///', get_test_data_dir(), '/user_test.db']))

        cls.guest = MockUser(name='t_guest', password='test', key='1okMSKUKlYxSvPn0sgfHM0SWd9zqNChyj5fbcIJgfKM=')
        cls.guest_analyst = MockUser(name='t_guest_analyst', password='test', key='mDsgjAM2iE543PySnTpPZr0u8KeGTPGzPjKJVO4I4Ww=')
        cls.superuser = MockUser(name='t_superuser', password='test', key='k2GKnNaA5UlENStVI4AEJKQ7BP9ZqO+21Cx746BjJDo=')
