from __future__ import annotations

import math
from pathlib import Path
from typing import TYPE_CHECKING, List

from entropython import metric_entropy
from pydantic import BaseModel

if TYPE_CHECKING:
    from io import FileIO

BLOCK_SIZE_MIN = 2**10  # 1 KiB
BLOCK_SIZE_MAX = 2**20  # 1 MiB


class Block(BaseModel):
    offset: int
    entropy: float


class Entropy(BaseModel):
    avg_entropy: float
    blocks: List[Block]
    blocksize: int


def get_entropy_analysis(file_handle: FileIO) -> Entropy:
    file = Path(file_handle.name)
    size = file.stat().st_size
    if size == 0:
        return Entropy(avg_entropy=0, blocksize=0, blocks=[])

    blocksize = _get_blocksize(size)
    blocks = []
    offset = 0
    with file.open('rb') as fp:
        while block := fp.read(blocksize):
            blocks.append(Block(offset=offset, entropy=metric_entropy(block)))
            offset += len(block)
    avg_entropy = _calculate_avg_entropy(blocks, size, blocksize)
    return Entropy(avg_entropy=avg_entropy, blocksize=blocksize, blocks=blocks)


def _get_blocksize(file_size: int) -> int:
    # this will always give 32 to 64 points to plot (except the file is smaller than 15 KiB or larger than 32 MiB)
    blocksize = 2 ** (math.floor(math.log2(file_size)) - 5)
    return min(BLOCK_SIZE_MAX, max(blocksize, BLOCK_SIZE_MIN))


def _calculate_avg_entropy(blocks: list[Block], file_size: int, blocksize: int) -> float:
    avg_entropy = 0
    for block in blocks[:-1]:
        avg_entropy += block.entropy * blocksize
    last_block_size = file_size - blocks[-1].offset
    avg_entropy += blocks[-1].entropy * last_block_size
    return avg_entropy / file_size
