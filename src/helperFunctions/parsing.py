import logging
from struct import unpack
from helperFunctions.process import complete_shutdown
from helperFunctions.dataConversion import make_unicode_string

try:
    import OpenSSL
except ImportError:
    complete_shutdown("Could not load pyOpenSSL: Install it via: pip3 install pyopenssl")

TLV_KNOWN_STARTS = [0x30]


def _get_start_and_size_of_der_field(binary=None, offset=None):
    if binary[offset + 1] > 127:
        length_of_length = binary[offset + 1] ^ 0x80
        logging.debug('[LOG] - Length {}'.format(length_of_length))
        form_string = _determine_format_string(length_of_length)
        return offset + 2 + length_of_length, unpack(form_string, binary[(offset + 2):(offset + 2 + length_of_length)])[0]
    else:
        return offset + 2, binary[offset + 1]


def _determine_format_string(length=None):
    if length not in [1, 2, 4]:
        logging.warning('Unregular format in DER encoding')
        return None
    formats = ['>b', '>h', None, '>i']
    return formats[length - 1]


def read_asn1_key(binary=None, offset=None):
    if binary[offset] not in TLV_KNOWN_STARTS:
        return None
    start, size = _get_start_and_size_of_der_field(binary=binary, offset=offset)
    try:
        key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_ASN1, binary[offset:start + size])
        text_key = make_unicode_string(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_TEXT, key))
        return text_key
    except OpenSSL.crypto.Error:
        logging.debug('Found PKCS#8 key signature, but looks false positive')
        return None


def read_pkcs_cert(binary=None, offset=None):
    if binary[offset] not in TLV_KNOWN_STARTS:
        return None
    start, size = _get_start_and_size_of_der_field(binary=binary, offset=offset)
    try:
        asn1_cert = OpenSSL.crypto.load_pkcs12(buffer=binary[offset:start + size])
        x509_cert = asn1_cert.get_certificate()
        text_cert = make_unicode_string(OpenSSL.crypto.dump_certificate(type=OpenSSL.crypto.FILETYPE_TEXT, cert=x509_cert))
        return text_cert
    except OpenSSL.crypto.Error:
        logging.debug('Found PKCS#12 certificate, but passphrase is missing or false positive.')
        return None


def read_ssl_cert(binary=None, start=None, end=None):
    try:
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, binary[start:end + 25])
        cert_text = make_unicode_string(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, cert))
        return cert_text
    except OpenSSL.crypto.Error:
        logging.debug('Found SSL certificate signature, but looks false positive')
        print(bcolors.FAIL, "Error", bcolors.ENDC)
        return None


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
