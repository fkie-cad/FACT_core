import logging
import os
from time import time
from typing import Union

from common_helper_files import get_binary_from_file, get_dir_of_file, get_files_in_dir

from helperFunctions.config import load_config
from helperFunctions.fileSystem import get_parent_dir
from helperFunctions.tag import TagColor
from helperFunctions.web_interface import ConnectTo
from objects.file import FileObject
from storage.db_interface_view_sync import ViewUpdater


class AnalysisBasePlugin:
    '''
    This is the base plugin. All plugins should be subclass of this.
    recursive flag: If True (default) recursively analyze included files
    '''
    VERSION = 'not set'
    SYSTEM_VERSION = None
    NAME = 'base'
    DEPENDENCIES = []

    timeout = None

    def __init__(self, config=None, plugin_path=None):
        self.config = config if config else load_config('main.cfg')
        self._sync_view(plugin_path)

    def process_object(self, file_object: FileObject) -> FileObject:  # pylint: disable=no-self-use
        '''
        This function must be implemented by the plugin
        '''
        return file_object

    def analyze_file(self, file_object: FileObject) -> FileObject:
        file_object.processed_analysis.update({self.NAME: {}})

        self.process_object(file_object)
        self._add_meta_data_to_result(file_object)

        return file_object

    def _add_meta_data_to_result(self, file_object: FileObject) -> FileObject:
        file_object.processed_analysis[self.NAME].update(self.init_dict())
        return file_object

# ---- internal functions ----

    def add_analysis_tag(self, file_object: FileObject, tag_name: str, value: str, color: str = TagColor.LIGHT_BLUE, propagate: bool = False):
        new_tag = {
            tag_name: {
                'value': value,
                'color': color,
                'propagate': propagate,
            },
            'root_uid': file_object.get_root_uid()
        }
        if 'tags' not in file_object.processed_analysis[self.NAME]:
            file_object.processed_analysis[self.NAME]['tags'] = new_tag
        else:
            file_object.processed_analysis[self.NAME]['tags'].update(new_tag)

    def init_dict(self):
        result_update = {'analysis_date': time(), 'plugin_version': self.VERSION}
        if self.SYSTEM_VERSION:
            result_update.update({'system_version': self.SYSTEM_VERSION})
        return result_update

    def _sync_view(self, plugin_path: str):
        if plugin_path:
            view_source = self._get_view_file_path(plugin_path)
            if view_source is not None:
                view = get_binary_from_file(view_source)
                with ConnectTo(ViewUpdater, self.config) as connection:
                    connection.update_view(self.NAME, view)

    def _get_view_file_path(self, plugin_path: str) -> Union[str, None]:
        plugin_path = get_parent_dir(get_dir_of_file(plugin_path))
        view_files = get_files_in_dir(os.path.join(plugin_path, 'view'))
        if not view_files:
            logging.debug('{}: No view available! Generic view will be used.'.format(self.NAME))
            return None
        if len(view_files) > 1:
            logging.warning('{}: Plug-in provides more than one view! \'{}\' is used!'.format(self.NAME, view_files[0]))
        return view_files[0]
