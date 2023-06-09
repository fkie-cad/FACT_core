from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.tag import TagColor
from objects.file import FileObject
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED

from ..internal.device_tree_utils import dump_device_trees


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Device Tree Plug-in
    '''

    NAME = 'device_tree'
    DESCRIPTION = 'get the device tree in text from the device tree blob'
    VERSION = '1.0.1'
    MIME_BLACKLIST = [*MIME_BLACKLIST_COMPRESSED, 'audio', 'image', 'video']
    FILE = __file__

    def process_object(self, file_object: FileObject):
        file_object.processed_analysis[self.NAME] = {'summary': []}

        device_trees = dump_device_trees(file_object.binary)
        if device_trees:
            file_object.processed_analysis[self.NAME]['device_trees'] = device_trees
            for result in device_trees:
                model = result.get('model')
                if model:
                    file_object.processed_analysis[self.NAME]['summary'].append(model)
            self.add_analysis_tag(
                file_object=file_object,
                tag_name=self.NAME,
                value=self.NAME.replace('_', ' '),
                color=TagColor.ORANGE,
                propagate=False,
            )

        return file_object
