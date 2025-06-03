from __future__ import annotations

import gzip
import io

DECOMPRESS_CHUNK_SIZE = 8_388_608  # 8 MiB


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
