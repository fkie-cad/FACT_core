class ComparePluginBase(object):
    '''
    This is the compare plug-in base class. All compare plug-ins should be derived from this class.
    '''

    NAME = 'base'
    DEPENDENCYS = []

    def __init__(self, plugin_administrator, config=None, db_interface=None):
        self.config = config
        self.plugin_administrator = plugin_administrator
        self.register_plugin()
        self.database = db_interface

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
