from analysis.YaraPluginBase import YaraBasePlugin


class AnalysisPlugin(YaraBasePlugin):
    NAME = 'known_vulnerabilities'
    DESCRIPTION = 'Rule based detection of known vulnerabilities like Heartbleed'
    DEPENDENCIES = ['software_components', 'file_hashes']
    VERSION = '0.1'
    FILE = __file__

    def __init__(self, plugin_administrator, config=None, recursive=True):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)
        self._software_rules = self._initialize_rules()

    def process_object(self, file_object):
        file_object = super().process_object(file_object)

        yara_results = file_object.processed_analysis.pop(self.NAME)
        binary_vulnerabilities, summary = self._post_process_yara_results(yara_results)

        software_vulnerabilies = self.check_software_components(file_object.processed_analysis['software_components'])

        file_object.processed_analysis[self.NAME] = dict()
        for name, vulnerability in software_vulnerabilies + binary_vulnerabilities:
            file_object.processed_analysis[self.NAME][name] = vulnerability

        file_object.processed_analysis[self.NAME]['summary'] = [item[0] for item in binary_vulnerabilities + software_vulnerabilies]

        return file_object

    def _post_process_yara_results(self, yara_results):
        summary = yara_results.pop('summary')
        new_results = list()
        for result in yara_results:
            meta = yara_results[result]['meta']
            new_results.append((result, meta))
        return new_results, summary

    def check_software_components(self, software_components_result):
        found_vulnerabilities = list()
        for software_component in software_components_result.keys():
            for rule in self._software_rules:
                if rule.software.lower() == software_component.lower():
                    component = software_components_result[software_component]
                    component_version = None

                    for version in component['meta']['version']:
                        if version:
                            component_version = version
                    if rule.is_vulnerable(component['rule'], version=component_version):
                        found_vulnerabilities.append((software_component, rule.get_dict()))
        return found_vulnerabilities

    def _initialize_rules(self):
        heartbleed_versions = ['1.0.1{}'.format(minor) for minor in 'abcde']
        heartbleed = SoftwareRule(score='high', description='The SSL Hearbleed bug allowing buffer overread', reliability='90')
        heartbleed.set_software('OpenSSL', versions=heartbleed_versions)

        return [heartbleed, ]


class BadRuleError(ValueError):
    pass


class SoftwareRule:
    def __init__(self, score, description, reliability):
        try:
            self.reliability = int(reliability)
            assert self.reliability in range(0, 101), 'reliability must be between 0 and 100'
            self.reliability = str(reliability)

            self.score = score
            assert self.score in ['low', 'medium', 'high'], ''

            self.description = description
            assert isinstance(self.description, str), 'description must be a string'

        except (AssertionError, ValueError, TypeError) as exception:
            raise BadRuleError(str(exception))

        self.software, self._versions = None, None

    def set_software(self, name, versions=None):
        self.software = name
        self._versions = versions if versions else []

    def is_vulnerable(self, software, version):
        assert self.software, 'function must not be called before software is set. See .set_software'

        if not self._versions:
            return True

        if version in self._versions:
            return True
        return False

    def get_dict(self):
        return dict(description=self.description, score=self.score, reliability=self.reliability)
