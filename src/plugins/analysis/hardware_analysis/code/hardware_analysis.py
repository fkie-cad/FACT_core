from typing import Optional

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Hardware Analysis Plug-in
    '''
    NAME = 'hardware_analysis'
    DESCRIPTION = 'Hardware Analysis Plug-in'
    DEPENDENCIES = ['cpu_architecture', 'elf_analysis', 'kernel_config']
    VERSION = '0.2'

    def __init__(self, plugin_adminstrator, config=None, recursive=True):

        self.config = config

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):

        # search for important information
        cpu_architecture = self.cpu_architecture_analysis(file_object)
        modinfo = self.get_modinfo(file_object)
        kernel_config = self.filter_kernel_config(file_object)

        # store the results
        file_object.processed_analysis[self.NAME] = {
            'cpu architecture': cpu_architecture,
            'modinfo section': modinfo,
            'kernel configuration': kernel_config
        }

        # propagate summary to parent objects
        file_object.processed_analysis[self.NAME]['summary'] = self.make_summary(cpu_architecture, modinfo, kernel_config)

        return file_object

    def cpu_architecture_analysis(self, file_object) -> Optional[str]:
        cpu_architecture = file_object.processed_analysis['cpu_architecture']['summary']

        if cpu_architecture == []:
            cpu_architecture = None
        else:
            cpu_architecture = cpu_architecture[0]

        return cpu_architecture

    def get_modinfo(self, file_object):
        # getting the information from the *.ko files .modinfo
        return file_object.processed_analysis['elf_analysis'].get('Output', {}).get('modinfo')

    def filter_kernel_config(self, file_object):
        kernel_config_dict = file_object.processed_analysis['kernel_config']
        kernel_config = kernel_config_dict.get('kernel_config')
        # FIXME: finer filter
        if isinstance(kernel_config, str):
            kernel_config_list = kernel_config.splitlines()
            kernel_config = [
                line
                for line in kernel_config_list
                if line and not line.startswith('#')
            ]

        else:
            kernel_config = None

        return kernel_config

    def make_summary(self, cpu_architecture, modinfo, kernel_config):
        summary = []

        if cpu_architecture is not None:
            summary.append(cpu_architecture)

        if modinfo is not None:
            summary.append('modinfo available')

        if kernel_config is not None:
            summary.append('kernel_config available')

        return summary
