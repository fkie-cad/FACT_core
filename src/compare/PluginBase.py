import logging
import os

from common_helper_files import get_files_in_dir, get_dir_of_file, get_binary_from_file

from helperFunctions.fileSystem import get_parent_dir
from helperFunctions.web_interface import ConnectTo
from storage.db_interface_view_sync import ViewUpdater


class ComparePluginBase(object):
    '''
    This is the compare plug-in base class. All compare plug-ins should be derived from this class.
    '''

    NAME = 'base'
    DEPENDENCYS = []

    def __init__(self, plugin_administrator, config=None, db_interface=None, plugin_path=None):
        self.config = config
        self.plugin_administrator = plugin_administrator
        self.register_plugin()
        self.database = db_interface
        if plugin_path:
            self._sync_view(plugin_path)

    def _sync_view(self, plugin_path):
        if plugin_path:
            view_source = self._get_view_file_path(plugin_path)
            if view_source is not None:
                view = get_binary_from_file(view_source)
                with ConnectTo(ViewUpdater, self.config) as connection:
                    connection.update_view(self.NAME, view)

    def _get_view_file_path(self, plugin_path):
        plugin_path = get_parent_dir(get_dir_of_file(plugin_path))
        view_files = get_files_in_dir(os.path.join(plugin_path, 'view'))
        if len(view_files) < 1:
            logging.debug('{}: No view available! Generic view will be used.'.format(self.NAME))
            return None
        elif len(view_files) > 1:
            logging.warning('{}: Plug-in provides more than one view! \'{}\' is used!'.format(self.NAME, view_files[0]))
        return view_files[0]

    def compare_function(self, fo_list):
        '''
        This function must be implemented by the plug-in.
        'fo_list' is a list with file_objects including analysis and all summaries
        this function should return a dictionary
        '''
        return {'dummy': {'all': 'dummy-content', 'collapse': False}}

    def compare(self, fo_list):
        '''
        This function is called by the compare module.
        '''
        missing_deps = self.check_dependencys(fo_list)
        if len(missing_deps) > 0:
            return {'Compare Skipped': {'all': 'Required analysis not present: {}'.format(missing_deps)}}
        else:
            return self.compare_function(fo_list)

    def check_dependencys(self, fo_list):
        missing_deps = []
        for item in fo_list:
            for dep in self.DEPENDENCYS:
                if dep not in item.processed_analysis:
                    missing_deps.append(dep)
        return missing_deps

    def register_plugin(self):
        self.plugin_administrator.register_plugin(self.NAME, self)
