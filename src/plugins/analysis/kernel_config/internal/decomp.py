import bz2
import gzip
import io
import lzma
import zlib
from typing import List


class GZDecompressor:
    @staticmethod
    def decompress(raw: bytes):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
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


_COMPRESSIONS = [
    {'magic': b'\037\213', 'cls': GZDecompressor},
    {'magic': b'\3757zXZ', 'cls': lzma.LZMADecompressor},
    {'magic': b'\135\0\0\0', 'cls': lzma.LZMADecompressor},
    {'magic': b'BZh', 'cls': bz2.BZ2Decompressor}
]

DECOMPRESS_CHUNK_SIZE = 8388608  # 8 MiB


def _collect_compression_indices(raw, magic_word: bytes) -> List[int]:
    indices = list()

    raw_offset = 0
    while True:
        raw_offset = raw.find(magic_word, raw_offset)
        if raw_offset < 0:
            break
        indices += [raw_offset]
        raw_offset += 1

    return indices


def _decompress_indices(raw: bytes, indices: List[int], decompressor: object) -> List[bytes]:
    result = list()
    for index in indices:
        try:
            decompressed = decompressor.decompress(raw[index:])
            if len(decompressed) > 0:
                result.append(decompressed)
        except (lzma.LZMAError, zlib.error, ValueError, OSError, EOFError):
            pass

    return result


def decompress(raw: bytes) -> List[bytes]:
    result = list()

    for compression in _COMPRESSIONS:
        indices = _collect_compression_indices(raw, compression['magic'])

        if len(indices) == 0:
            continue

        decompressor = compression['cls']()

        result = _decompress_indices(raw, indices, decompressor)

        if len(result) > 0:
            break

    return result
