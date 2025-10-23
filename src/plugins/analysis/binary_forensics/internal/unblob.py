from __future__ import annotations

import re

from pydantic import BaseModel

UNBLOB_REGEX = re.compile(r'start: (\d+), end: \d+, size: (\d+), type: (\w+)')


class UnblobResult(BaseModel):
    offset: int
    size: int
    type: str


def get_unblob_result(unpacking_result: dict) -> list[UnblobResult] | None:
    if unpacking_result['plugin_used'] != 'generic_carver':
        return None
    matches = UNBLOB_REGEX.findall(unpacking_result.get('output', ''))
    if not matches:
        return None
    return [UnblobResult(offset=offset, size=size, type=type_) for offset, size, type_ in matches]
