import json


def dump(data) -> str:
    return json.dumps(data, sort_keys=True)
