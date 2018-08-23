from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.parsing import read_asn1_key, read_pkcs_cert, read_ssl_cert
from helperFunctions.tag import TagColor


class AnalysisPlugin(YaraBasePlugin):
    '''
    Searches for known Crypto material (e.g., public and private keys)
    '''
    NAME = 'crypto_material'
    DESCRIPTION = 'detects crypto material like SSH keys and SSL certificates'
    STARTEND = ['PgpPublicKeyBlock', 'PgpPrivateKeyBlock', 'PgpPublicKeyBlock_GnuPG', 'genericPublicKey',
                'SshRsaPrivateKeyBlock', 'SSLPrivateKey']
    STARTONLY = ['SshRsaPublicKeyBlock']
    MIME_BLACKLIST = ['filesystem']
    PKCS8 = 'Pkcs8PrivateKey'
    PKCS12 = 'Pkcs12Certificate'
    SSLCERT = 'SSLCertificate'
    VERSION = '0.5.2'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        file_object = super().process_object(file_object)
        analysis_result = {'summary': []}
        if len(file_object.processed_analysis[self.NAME]['summary']) > 0:
            for match in file_object.processed_analysis[self.NAME]['summary']:
                if match in self.STARTEND:
                    self.store_current_match_in_result(file_object=file_object, match=match, result=analysis_result, parsing_function=self.extract_labeled_keys)
                elif match in self.STARTONLY:
                    self.store_current_match_in_result(file_object=file_object, match=match, result=analysis_result, parsing_function=self.extract_start_only_key)
                elif match == self.PKCS8:
                    self.store_current_match_in_result(file_object=file_object, match=match, result=analysis_result, parsing_function=self.get_pkcs8_key)
                elif match == self.PKCS12:
                    self.store_current_match_in_result(file_object=file_object, match=match, result=analysis_result, parsing_function=self.get_pkcs12_cert)
                elif match == self.SSLCERT:
                    self.store_current_match_in_result(file_object=file_object, match=match, result=analysis_result, parsing_function=self.get_ssl_cert)

        file_object.processed_analysis[self.NAME] = analysis_result
        self._add_private_key_tag(file_object, analysis_result)
        return file_object

    def store_current_match_in_result(self, file_object, match, result, parsing_function):
        tmp = file_object.processed_analysis[self.NAME][match]
        keys = parsing_function(strings=tmp['strings'], binary=file_object.binary)
        if len(keys) > 0:
            result[match] = dict()
            result[match]['material'] = keys
            result[match]['count'] = len(keys)
            result['summary'].append(match)

    def extract_labeled_keys(self, strings=None, binary=None, min_key_len=128):
        return [binary[offset[0]:offset[1]].decode(encoding='utf_8', errors='replace') for offset in self.get_offset_pairs(strings) if offset[1] - offset[0] > min_key_len]

    @staticmethod
    def extract_start_only_key(strings=None, binary=None):
        return [string[2].decode(encoding='utf_8', errors='replace') for string in strings if string[1] == '$start_string']

    @staticmethod
    def get_pkcs8_key(strings=None, binary=None):
        keys = []
        for string in strings:
            index, _, _ = string
            key = read_asn1_key(binary=binary, offset=index)
            if key is not None:
                keys.append(key)
        return keys

    @staticmethod
    def get_pkcs12_cert(strings=None, binary=None):
        keys = []
        for string in strings:
            index, _, _ = string
            text_cert = read_pkcs_cert(binary=binary, offset=index)
            if text_cert is not None:
                keys.append(text_cert)
        return keys

    def get_ssl_cert(self, strings=None, binary=None):
        contents = []
        for pair in self.get_offset_pairs(strings=strings):
            start_index, end_index = pair
            text_cert = read_ssl_cert(binary=binary, start=start_index, end=end_index)
            if text_cert is not None:
                contents.append(text_cert)
        return contents

    @staticmethod
    def get_offset_pairs(strings=[]):
        # Nasty if - elif structure necessary to prevent code duplication for different string pairs - keyword: $gnupg_version_string
        strings.sort(key=lambda x: x[0])
        pairs = []
        for index in range(len(strings) - 1):
            if strings[index][1] == '$start_string' and strings[index + 1][1] == '$end_string':
                end_index = strings[index + 1][0] + len(strings[index + 1][2])
                pairs.append((strings[index][0], end_index))
            elif strings[index][1] == '$start_string' and strings[index + 1][1] == '$gnupg_version_string' and len(strings) > index + 2:
                if strings[index][1] == '$start_string' and strings[index + 2][1] == '$end_string':
                    end_index = strings[index + 2][0] + len(strings[index + 2][2])
                    pairs.append((strings[index][0], end_index))
        return pairs

    def _add_private_key_tag(self, file_object, result):
        if any('private' in key.lower() for key in result):
            self.add_analysis_tag(
                file_object=file_object,
                tag_name='private_key_inside',
                value='Private Key Found',
                color=TagColor.ORANGE,
                propagate=True
            )
