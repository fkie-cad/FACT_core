from __future__ import annotations

import abc
import logging
import re
from base64 import b64decode
from typing import Optional

import pydantic
from pydantic import Field

from .crack_password import crack_hash

USER_NAME_REGEX = rb'[a-zA-Z_][a-zA-Z0-9_-]{2,16}'
DES_HASH_LENGTH = 13


class CredentialResult(pydantic.BaseModel):
    username: str = Field(description='The username.')
    full_entry: str = Field(description='The full entry in unparsed form.')
    type: str = Field(description='The type of credential (UNIX, htpasswd, etc.).')
    password_hash: Optional[str] = Field(description='The password in hashed form.', default=None)
    password: Optional[str] = Field(description='The password (if the hash was available and cracked).', default=None)
    error: Optional[str] = Field(
        description='Error message (if cracking the password hash was not successful).',
        default=None,
    )


class CredentialFinder(abc.ABC):
    REGEX_LIST: tuple[re.Pattern]

    @classmethod
    def find_credentials(cls, file_contents: bytes) -> list[CredentialResult]:
        return [
            cls._parse_entry(pw_entry)
            for passwd_regex in cls.REGEX_LIST
            for pw_entry in passwd_regex.findall(file_contents)
        ]

    @staticmethod
    @abc.abstractmethod
    def _parse_entry(entry: bytes) -> CredentialResult:
        ...


class UnixCredentialFinder(CredentialFinder):
    REGEX_LIST = (
        # passwd entry without password hash
        re.compile(USER_NAME_REGEX + rb':[x!*]?:\d{1,5}:\d{0,5}(?::[^:\n]{0,64}){2}:(?:/[^\n"\']+)?'),
        # 1 = MD5, 2/2a/2y = Blowfish, 5 = SHA256, 6 = SHA512, y = yescrypt
        re.compile(USER_NAME_REGEX + rb':\$(?:1|2|2a|2y|5|6|y)\$[a-zA-Z0-9./+]*\$[a-zA-Z0-9./+]{16,128}={0,2}'),
        re.compile(USER_NAME_REGEX + rb':[a-zA-Z0-9./=]{13}:\d*:\d*:'),  # DES
    )

    @staticmethod
    def _parse_entry(entry: bytes) -> CredentialResult:
        user_name, pw_hash, *_ = entry.split(b':')
        password, error = None, None
        try:
            if pw_hash.startswith(b'$') or _is_des_hash(pw_hash):
                password, error = crack_hash(b':'.join((user_name, pw_hash)))
        except (IndexError, AttributeError, TypeError):
            error = f'Unsupported password format: {entry}'
            logging.warning(error, exc_info=True)
        return CredentialResult(
            username=_to_str(user_name),
            full_entry=_to_str(entry),
            type='unix',
            password_hash=_to_str(pw_hash),
            password=password,
            error=error,
        )


def _is_des_hash(pw_hash: str) -> bool:
    return len(pw_hash) == DES_HASH_LENGTH


class HtpasswdCredentialFinder(CredentialFinder):
    REGEX_LIST = (
        re.compile(USER_NAME_REGEX + rb':\$apr1\$[a-zA-Z0-9./+=]+\$[a-zA-Z0-9./+]{22}'),  # MD5 apr1
        re.compile(USER_NAME_REGEX + rb':\{SHA}[a-zA-Z0-9./+]{27}='),  # SHA-1
    )

    @staticmethod
    def _parse_entry(entry: bytes) -> CredentialResult:
        user_name, pw_hash = entry.split(b':')
        password, error = crack_hash(entry)
        return CredentialResult(
            username=_to_str(user_name),
            full_entry=_to_str(entry),
            type='http',
            password_hash=_to_str(pw_hash),
            password=password,
            error=error,
        )


class MosquittoCredentialFinder(CredentialFinder):
    REGEX_LIST = (re.compile(rb'[a-zA-Z][a-zA-Z0-9_-]{2,15}:\$6\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/]{86}=='),)

    @staticmethod
    def _parse_entry(entry: bytes) -> CredentialResult:
        user, _, _, salt_hash, passwd_hash, *_ = re.split(r'[:$]', _to_str(entry))
        passwd_entry = f'{user}:$dynamic_82${b64decode(passwd_hash).hex()}$HEX${b64decode(salt_hash).hex()}'
        password, error = crack_hash(passwd_entry.encode(), '--format=dynamic_82')
        return CredentialResult(
            username=user,
            full_entry=_to_str(entry),
            type='mosquitto',
            password_hash=passwd_entry,
            password=password,
            error=error,
        )


def _to_str(byte_str: bytes) -> str:
    """
    result entries must be converted from `bytes` to `str` in order to be saved as JSON
    """
    return byte_str.decode(errors='replace')
