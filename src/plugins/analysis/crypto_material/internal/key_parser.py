from __future__ import annotations

import logging
from struct import unpack
from typing import TYPE_CHECKING

import OpenSSL.crypto as ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

from helperFunctions.data_conversion import make_unicode_string

if TYPE_CHECKING:
    import io

TLV_KNOWN_STARTS = {0x30}
LENGTH_TO_FORMAT = {
    1: '>b',
    2: '>h',
    4: '>i',
}
DER_LIMIT = 0x80
DER_HEADER_SIZE = 2
_PEM_CERT_HEADER_VARIANTS = (b'CA CERTIFICATE', b'TRUSTED CERTIFICATE', b'X509 CERTIFICATE')


def _normalize_pem_cert_headers(data: bytes) -> bytes:
    for variant in _PEM_CERT_HEADER_VARIANTS:
        data = data.replace(b'BEGIN ' + variant, b'BEGIN CERTIFICATE')
        data = data.replace(b'END ' + variant, b'END CERTIFICATE')
    return data


def _read_der_key(file_handle: io.FileIO, offset: int) -> bytes:
    file_handle.seek(offset + 1)
    value = int.from_bytes(file_handle.read(1), byteorder='little')
    # The field at offset + 1 is the length field. If the value is > 0x80, the field contains only the size (+0x80)
    # and the actual length is in the next field
    if value >= DER_LIMIT:
        value ^= DER_LIMIT
        logging.debug(f'[LOG] - Length {value}')
        length = unpack(_determine_format_string(value), file_handle.read(value))[0] + value
    else:
        length = value
    # we need to reset the file pointer because we need the entire key (including the length field)
    file_handle.seek(offset)
    return file_handle.read(length + DER_HEADER_SIZE)


def _determine_format_string(length: int | None) -> str | None:
    if length not in LENGTH_TO_FORMAT:
        raise ValueError('Irregular format in DER encoding')
    return LENGTH_TO_FORMAT[length]


def read_asn1_key(file_handle: io.FileIO, offset: int) -> str | None:
    file_handle.seek(offset)
    start = int.from_bytes(file_handle.read(1), byteorder='little')
    if start not in TLV_KNOWN_STARTS:
        return None
    try:
        file_handle.seek(offset)
        key_data = _read_der_key(file_handle=file_handle, offset=offset)
        key = ssl.load_privatekey(ssl.FILETYPE_ASN1, key_data)
        # FixMe: this produces a deprecation warning -> create actual structured output instead of text
        return make_unicode_string(ssl.dump_privatekey(ssl.FILETYPE_TEXT, key))
    except ssl.Error:
        logging.debug('Found PKCS#8 key signature, but looks false positive')
        return None
    except TypeError:
        logging.warning('Found PKCS#8 key signature but openssl binding could not decode it.')
        return None


def read_pkcs_cert(file_handle: io.FileIO, offset: int) -> str | None:
    file_handle.seek(offset)
    value = int.from_bytes(file_handle.read(1), byteorder='little')
    if value not in TLV_KNOWN_STARTS:
        return None
    try:
        key_data = _read_der_key(file_handle=file_handle, offset=offset)
        _, certificate, _ = pkcs12.load_key_and_certificates(key_data, None)
        x509_cert = ssl.load_certificate(ssl.FILETYPE_PEM, certificate.public_bytes(serialization.Encoding.PEM))
        return make_unicode_string(ssl.dump_certificate(type=ssl.FILETYPE_TEXT, cert=x509_cert))
    except ValueError:
        logging.debug('Found PKCS#12 certificate, but passphrase is missing or false positive.')
        return None


def read_ssl_cert(file_handle: io.FileIO, start: int, end: int) -> str | None:
    try:
        file_handle.seek(start)
        key_data = file_handle.read(end - start + 25)
        key_data = _normalize_pem_cert_headers(key_data)
        cert = ssl.load_certificate(ssl.FILETYPE_PEM, key_data)
        return make_unicode_string(ssl.dump_certificate(ssl.FILETYPE_TEXT, cert))
    except ssl.Error:
        logging.debug('Found SSL certificate signature, but looks false positive')
        return None


def read_ec_der_key(file_handle: io.FileIO, offset: int) -> str | None:
    try:
        file_handle.seek(offset)
        key_data = _read_der_key(file_handle, offset)
        private_key = serialization.load_der_private_key(key_data, password=None)
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return make_unicode_string(pem_data)
    except (ValueError, TypeError, ssl.Error) as error:
        logging.debug('Found EC private key signature, but looks false positive: %s', error)
        return None


def read_openssh_private_key(file_handle: io.FileIO, start: int, end: int) -> str | None:
    file_handle.seek(start)
    key_data = file_handle.read(end - start + 25)
    try:
        private_key = serialization.load_ssh_private_key(key_data, password=None)
    except (ValueError, TypeError) as error:
        logging.debug('OpenSSH private key is encrypted or malformed, returning raw block: %s', error)
        return make_unicode_string(key_data)
    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return make_unicode_string(pem_data)


def read_encrypted_private_key_marker(file_handle: io.FileIO, offset: int) -> str | None:
    try:
        file_handle.seek(offset)
        key_data = _read_der_key(file_handle, offset)
        private_key = serialization.load_der_private_key(key_data, password=None)
        if private_key is not None:
            logging.debug('Encrypted private key signature, but key is not encrypted')
            return None
    except (ValueError, TypeError):
        # expected: key is encrypted and cannot be loaded without a password
        return 'Encrypted PKCS8 private key (encrypted, cannot be decrypted without password)'
    return None


def read_pkcs7(file_handle: io.FileIO, offset: int) -> str | None:
    try:
        file_handle.seek(offset)
        key_data = _read_der_key(file_handle, offset)
        certs = pkcs7.load_der_pkcs7_certificates(key_data)
        if not certs:
            return 'PKCS7/CMS object (no certificates embedded)'
        certs_text = []
        for cert in certs:
            pem_data = cert.public_bytes(serialization.Encoding.PEM)
            x509_cert = ssl.load_certificate(ssl.FILETYPE_PEM, pem_data)
            certs_text.append(make_unicode_string(ssl.dump_certificate(ssl.FILETYPE_TEXT, x509_cert)))
        return '\n'.join(certs_text)
    except (ssl.Error, ValueError) as error:
        logging.debug('Found PKCS7 signature, but looks false positive: %s', error)
        return None


def read_pkcs7_pem(file_handle: io.FileIO, start: int, end: int) -> str | None:
    try:
        file_handle.seek(start)
        pem_data = file_handle.read(end - start + 25)
        certs = pkcs7.load_pem_pkcs7_certificates(pem_data)
        if not certs:
            return 'PKCS7/CMS object (no certificates embedded)'
        certs_text = []
        for cert in certs:
            pem_cert = cert.public_bytes(serialization.Encoding.PEM)
            x509_cert = ssl.load_certificate(ssl.FILETYPE_PEM, pem_cert)
            certs_text.append(make_unicode_string(ssl.dump_certificate(ssl.FILETYPE_TEXT, x509_cert)))
        return '\n'.join(certs_text)
    except (ssl.Error, ValueError) as error:
        logging.debug('Found PKCS7 PEM signature, but looks false positive: %s', error)
        return None
