import lief

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Hardware Analysis Plug-in
    '''
    NAME = 'hardware_analysis'
    DESCRIPTION = 'Hardware Analysis Plug-in'
    DEPENDENCIES = ['cpu_architecture', 'elf_analysis', 'kernel_config']
    VERSION = '0.2.1'

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        '''
        self.config = config

        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):

        # init the data

        cpu_architecture_dict = file_object.processed_analysis['cpu_architecture']
        kernel_config_dict = file_object.processed_analysis['kernel_config']

        # getting the cpu architecture (test needed?)
        cpu_architecture = list(cpu_architecture_dict.keys())[0]

        if cpu_architecture == "summary":
            cpu_architecture = "no information"

        # getting the information from the *.ko files .modinfo
        elf_analysis = str(file_object.file_name)

        if elf_analysis.endswith(".ko"):

            binary = lief.parse(file_object.file_path)

            if isinstance(binary, type(None)):

                for section in binary.sections:

                    if section.name == ".modinfo":

                        elf_analysis = bytes(section.content).decode()
                        elf_analysis = elf_analysis.replace("\x00", "\n")
                        break
                    
                    # no .modinfo
                    elf_analysis = "no information"

            else:
                # binary is nonetype
                elf_analysis = "no information"

        else:
            elf_analysis = "no information"

        # getting the kernel configs
        kernel_config = kernel_config_dict.get("kernel_config")

        if isinstance(kernel_config, str):

            kernel_config_list = kernel_config.splitlines()

            kernel_config = ""

            for line in kernel_config_list:

                if not line.startswith("#"):
                    kernel_config = kernel_config + line + "\n"

        else:
            kernel_config = "no information"

        # store the results
        file_object.processed_analysis[self.NAME] = dict()
        file_object.processed_analysis[self.NAME]['cpu architecture'] = cpu_architecture
        file_object.processed_analysis[self.NAME]['*.ko ".modinfo"'] = elf_analysis
        file_object.processed_analysis[self.NAME]['kernel configuration'] = kernel_config

        # propagate some summary to parent objects

        if cpu_architecture != "no information":

            if (elf_analysis == "no information") & (kernel_config == "no information"):
                file_object.processed_analysis[self.NAME]['summary'] = [f'{cpu_architecture}']

            elif (elf_analysis != "no information") & (kernel_config != "no information"):
                file_object.processed_analysis[self.NAME]['summary'] = [f'{cpu_architecture} - .modinfo available - kernel configuration available']

            elif (elf_analysis != "no information") & (kernel_config == "no information"):
                file_object.processed_analysis[self.NAME]['summary'] = [f'{cpu_architecture} - .modinfo available']

            elif (elf_analysis == "no information") & (kernel_config != "no information"):
                file_object.processed_analysis[self.NAME]['summary'] = [f'{cpu_architecture} - kernel configuration available']

        else:
            if (elf_analysis == "no information") & (kernel_config == "no information"):
                file_object.processed_analysis[self.NAME]['summary'] = ['']

            elif (elf_analysis != "no information") & (kernel_config != "no information"):
                file_object.processed_analysis[self.NAME]['summary'] = ['.modinfo available - kernel configuration available']

            elif (elf_analysis != "no information") & (kernel_config == "no information"):
                file_object.processed_analysis[self.NAME]['summary'] = ['.modinfo available']

            elif (elf_analysis == "no information") & (kernel_config != "no information"):
                file_object.processed_analysis[self.NAME]['summary'] = ['kernel configuration available']

        return file_object
