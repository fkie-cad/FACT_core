from typing import Dict, List, Union

JsonType = Union[str, int, float, bool, None, 'JsonDict', 'JsonList']
JsonDict = Dict[str, JsonType]  # JSON compatible dict
JsonList = List[JsonType]  # JSON compatible list
