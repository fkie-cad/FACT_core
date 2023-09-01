from __future__ import annotations

import bz2
import gzip
import io
import lzma
import zlib
from typing import Protocol


class GZDecompressor:
    @staticmethod
    def decompress(data: bytes):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
            decompressed = b''

            try:
                while True:
                    chunk = stream.read1(DECOMPRESS_CHUNK_SIZE)
                    if not chunk:
                        break
                    decompressed += chunk
            except (OSError, EOFError):
                pass

        return decompressed


class Decompressor(Protocol):
    def decompress(self, data: bytes) -> bytes:
        ...


_COMPRESSIONS: list[tuple[bytes, Decompressor]] = [
    (b'\037\213', GZDecompressor),
    (b'\3757zXZ', lzma.LZMADecompressor),  # type: ignore[list-item]
    (b'\135\0\0\0', lzma.LZMADecompressor),  # type: ignore[list-item]
    (b'BZh', bz2.BZ2Decompressor),  # type: ignore[list-item]
]

DECOMPRESS_CHUNK_SIZE = 8388608  # 8 MiB


def _collect_compression_indices(raw, magic_word: bytes) -> list[int]:
    indices = []

    raw_offset = 0
    while True:
        raw_offset = raw.find(magic_word, raw_offset)
        if raw_offset < 0:
            break
        indices += [raw_offset]
        raw_offset += 1

    return indices


def _decompress_indices(raw: bytes, indices: list[int], decompressor: Decompressor) -> list[bytes]:
    result = []
    for index in indices:
        try:
            decompressed = decompressor.decompress(raw[index:])
            if len(decompressed) > 0:
                result.append(decompressed)
        except (lzma.LZMAError, zlib.error, ValueError, OSError, EOFError):
            pass

    return result


def decompress(raw: bytes) -> list[bytes]:
    result = []

    for magic, decompression_func in _COMPRESSIONS:
        indices = _collect_compression_indices(raw, magic)

        if len(indices) == 0:
            continue

        result = _decompress_indices(raw, indices, decompression_func)

        if len(result) > 0:
            break

    return result
