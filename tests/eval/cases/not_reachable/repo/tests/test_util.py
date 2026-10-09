from app.util import dump


def test_dump():
    assert dump({"b": 1, "a": 2}) == '{"a": 2, "b": 1}'
