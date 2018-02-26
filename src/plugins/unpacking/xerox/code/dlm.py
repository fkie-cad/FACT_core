name = 'XeroxDLM'
mime_patterns = ['firmware/xerox-dlm']
version = '0.3'


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''

    xdlm = XeroxDLM(file_path)
    meta_data = _create_meta_dict(xdlm)

    binary_path = '{}/dlm_data.bin'.format(tmp_dir)
    xdlm.write_data_to_file(binary_path)

    return meta_data


def _create_meta_dict(xeroxdlm):
    xerox_header = {}
    xerox_header['dlm_signature'] = xeroxdlm.get_signature()
    xerox_header['dlm_version'] = xeroxdlm.get_dlm_version()
    xerox_header['dlm_name'] = xeroxdlm.get_dlm_name()
    xerox_header['dlm_extraction_criteria'] = xeroxdlm.get_dlm_extraction_criteria()
    return xerox_header


class XeroxDLM:
    def __init__(self, firmware_file):
        self.firmware_file = firmware_file
        self.header_end_offset = None
        self.dlm_signature = None
        self.dlm_version = None
        self.dlm_name = None
        self.dlm_extraction_criteria = None

    def __str__(self):
        return 'DLM-Signature: {}\nDLM-Version: {}\nDLM-Name: {}\nDLM-Extraction-Criteria: {}'.format(self.get_signature(), self.get_dlm_version(), self.get_dlm_name(), self.get_dlm_extraction_criteria())

    def get_header_end_offset(self):
        if self.header_end_offset is not None:
            return self.header_end_offset

        with open(self.firmware_file, 'rb') as firmware:
            header = firmware.read(1000)
            search_pattern = b'%%XRXend'
            offset = header.find(search_pattern)
        return offset + len(search_pattern)

    def _get_header(self):
        with open(self.firmware_file, 'rb') as firmware:
            return firmware.read(self.get_header_end_offset())

    def _get_dlm_field(self, search_pattern):
        header = self._get_header()
        offset = header.find(search_pattern) + len(search_pattern) + 2
        header = header[offset:]
        offset = header.find(b'"')
        return header[:offset]

    def get_signature(self):
        if self.dlm_signature is None:
            self.dlm_signature = self._get_dlm_field(b'%%OID_ATT_DLM_SIGNATURE').decode('ascii')
        return self.dlm_signature

    def get_dlm_version(self):
        if self.dlm_version is None:
            self.dlm_version = self._get_dlm_field(b'%%OID_ATT_DLM_VERSION').decode('ascii')
        return self.dlm_version

    def get_dlm_name(self):
        if self.dlm_name is None:
            self.dlm_name = self._get_dlm_field(b'%%OID_ATT_DLM_NAME').decode('ascii')

        return self.dlm_name

    def get_dlm_extraction_criteria(self):
        if self.dlm_extraction_criteria is None:
            self.dlm_extraction_criteria = self._get_dlm_field(b'%%OID_ATT_DLM_EXTRACTION_CRITERIA').decode('ascii')
        return self.dlm_extraction_criteria

    def write_data_to_file(self, data_file):
        with open(self.firmware_file, 'rb') as firmware:
            offset = self.get_header_end_offset() + 1
            firmware.seek(offset)
            block_size = 1024
            with open(data_file, 'wb') as tgz:
                while True:
                    data_block = firmware.read(block_size)
                    tgz.write(data_block)
                    if len(data_block) < block_size:
                        break

# ----> Do not edit below this line <----


def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))
