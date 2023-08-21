import logging
from struct import unpack

from OpenSSL import crypto

from helperFunctions.data_conversion import make_unicode_string

TLV_KNOWN_STARTS = [0x30]


def _get_start_and_size_of_der_field(binary=None, offset=None):
    if binary[offset + 1] > 127:  # noqa: PLR2004
        length_of_length = binary[offset + 1] ^ 0x80
        logging.debug(f'[LOG] - Length {length_of_length}')
        form_string = _determine_format_string(length_of_length)
        return (
            offset + 2 + length_of_length,
            unpack(form_string, binary[(offset + 2) : (offset + 2 + length_of_length)])[0],
        )
    return offset + 2, binary[offset + 1]


def _determine_format_string(length=None):
    if length not in [1, 2, 4]:
        logging.warning('Unregular format in DER encoding')
        return None
    formats = ['>b', '>h', None, '>i']
    return formats[length - 1]


def read_asn1_key(binary: bytes, offset: int):
    if binary[offset] not in TLV_KNOWN_STARTS:
        return None
    start, size = _get_start_and_size_of_der_field(binary=binary, offset=offset)
    try:
        key = crypto.load_privatekey(crypto.FILETYPE_ASN1, binary[offset : start + size])
        return make_unicode_string(crypto.dump_privatekey(crypto.FILETYPE_TEXT, key))
    except crypto.Error:
        logging.debug('Found PKCS#8 key signature, but looks false positive')
        return None
    except TypeError:
        logging.warning('Found PKCS#8 key signature but openssl binding could not decode it.')
        return None


def read_pkcs_cert(binary: bytes, offset: int):
    if binary[offset] not in TLV_KNOWN_STARTS:
        return None
    start, size = _get_start_and_size_of_der_field(binary=binary, offset=offset)
    try:
        x509_cert = crypto.load_pkcs12(buffer=binary[offset : start + size]).get_certificate()
        return make_unicode_string(crypto.dump_certificate(type=crypto.FILETYPE_TEXT, cert=x509_cert))
    except crypto.Error:
        logging.debug('Found PKCS#12 certificate, but passphrase is missing or false positive.')
        return None


def read_ssl_cert(binary: bytes, start: int, end: int):
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, binary[start : end + 25])
        return make_unicode_string(crypto.dump_certificate(crypto.FILETYPE_TEXT, cert))
    except crypto.Error:
        logging.debug('Found SSL certificate signature, but looks false positive')
        return None
