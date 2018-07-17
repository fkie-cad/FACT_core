from base64 import b64decode
from common_helper_files import get_binary_from_file
import logging
import re
from struct import unpack
import sys

from helperFunctions.dataConversion import make_unicode_string


ENCODING_OVERHEAD = 0.33


class DskOne(object):
    '''
    DSK 1.0 Container Format used by Xerox
    '''

    HEADERSIZE = 0x18

    def __init__(self, file_path, raw=None):
        self.errors = []
        self.warnings = []
        if raw is None:
            self.raw = get_binary_from_file(file_path)
        else:
            self.raw = raw
        self.parse_header()
        self.extract_payload()
        self.log_errors_and_warnings()

    def get_meta_dict(self):
        meta = {}
        if len(self.errors) > 0:
            meta['unpack errors'] = self.errors
        if len(self.warnings) > 0:
            meta['unpack warnings'] = self.warnings
        if self.payload_size:
            meta['payload size'] = self.payload_size
            meta['encoding_overhead'] = ENCODING_OVERHEAD
        return meta

    def parse_header(self):
        try:
            self.header = unpack('<c6sxxxcxI', self.raw[0:16])
        except Exception as e:
            self.errors.append('could not parse header: {} - {}'.format(sys.exc_info()[0].__name__, e))
            self.header = None
            self.payload_size = None
        else:
            self.payload_size = self.header[3]
            self.check_validity()

    def extract_payload(self):
        if len(self.errors) == 0:
            self.encoded_payload = self.raw[self.HEADERSIZE:self.HEADERSIZE + self.payload_size]
            self.decoded_payload = b64decode(self.encoded_payload)
        else:
            logging.error('extraction aborted due to errors')

    def check_validity(self):
        if self.header[1] != b'DSK1.0':
            self.errors.append('DSK magic string missing')
        if self.payload_size > len(self.raw) - self.HEADERSIZE:
            self.errors.append('payload length longer than file: {} -> {}'.format(self.payload_size, len(self.raw)))
        if self.payload_size + self.HEADERSIZE < len(self.raw):
            self.warnings.append('data after payload')

    def log_errors_and_warnings(self):
        if len(self.errors) > 0:
            logging.error('Errors occured: {}'.format('\n'.join(self.errors)))
        if len(self.warnings) > 0:
            logging.warning('Warnings occured: {}'.format('\n'.join(self.warnings)))


class ExtendedDskOne(object):

    DSK_HEADER = re.compile(b'\x1bDSK1.0')

    def __init__(self, file_path):
        self.raw = get_binary_from_file(file_path)
        self._get_dsk()
        if self.decoded_payload is not None:
            self._get_identifier()

    def get_meta_dict(self):
        return self.meta

    def _get_dsk(self):
        dsk_match = self.DSK_HEADER.search(self.raw)
        if dsk_match:
            self.dsk_file_postion = dsk_match.start()
            dsk_file_raw = self.raw[self.dsk_file_postion:]
            self.dsk_file = DskOne(None, raw=dsk_file_raw)
            self.meta = self.dsk_file.get_meta_dict()
            self.decoded_payload = self.dsk_file.decoded_payload
        else:
            logging.error('Could not find DSK header!')
            self.meta = {'Extended DSK error': 'Could not find DSK header!'}
            self.decoded_payload = None

    def _get_identifier(self):
        self.meta['Extended DSK Identifier'] = make_unicode_string(self.raw[0:self.dsk_file_postion])
