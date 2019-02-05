from helperFunctions.config import get_config_for_testing


class MockFSOrganizer:
    def __init__(self, config):
        pass

    def store_file(self, file_object):
        pass

    def delete_file(self, uid):
        pass


class MockDbInterface:
    def __init__(self, config):
        self._objects = dict()

    def existence_quick_check(self, uid):
        return uid in self._objects

    def add_object(self, fo_fw):
        self._objects[fo_fw.uid] = fo_fw

    def get_specific_fields_of_db_entry(self, uid, field_dict):
        pass


def initialize_config(tmp_dir):
    config = get_config_for_testing(temp_dir=tmp_dir)

    # Database
    config.set('data_storage', 'main_database', 'tmp_integration_tests')
    config.set('data_storage', 'intercom_database_prefix', 'tmp_integration_tests')
    config.set('data_storage', 'statistic_database', 'tmp_integration_tests')
    config.set('data_storage', 'view_storage', 'tmp_view_storage')

    # Analysis
    config.add_section('ip_and_uri_finder')
    config.set('ip_and_uri_finder', 'signature_directory', 'analysis/signatures/ip_and_uri_finder/')
    config.add_section('default_plugins')
    config.set('default_plugins', 'plugins', 'file_hashes')

    # Unpacker
    config.set('unpack', 'threads', '2')
    config.set('ExpertSettings', 'unpack_throttle_limit', '20')

    # Compare
    config.set('ExpertSettings', 'ssdeep_ignore', '80')
    config.set('ExpertSettings', 'block_delay', '1')
    config.set('ExpertSettings', 'throw_exceptions', 'true')

    return config
