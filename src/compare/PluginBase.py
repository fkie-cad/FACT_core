from helperFunctions.dependency import get_unmatched_dependencies
from plugins.base import BasePlugin
from abc import abstractmethod


class CompareBasePlugin(BasePlugin):
    '''
    This is the compare plug-in base class. All compare plug-ins should be derived from this class.
    '''

    def __init__(self, plugin_administrator, config=None, db_interface=None, plugin_path=None):
        super().__init__(plugin_administrator, config=config, plugin_path=plugin_path)
        self.database = db_interface
        self.register_plugin()

    @abstractmethod
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
        missing_deps = get_unmatched_dependencies(fo_list, self.DEPENDENCIES)
        if len(missing_deps) > 0:
            return {'Compare Skipped': {'all': 'Required analysis not present: {}'.format(missing_deps)}}
        else:
            return self.compare_function(fo_list)
