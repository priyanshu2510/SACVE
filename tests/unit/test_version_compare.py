import pytest

from src.utils.version_compare import compare_versions, is_less_than, versions_equal


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("1.2.0", "1.2", 0),
        ("v1.1.12", "1.1.12", 0),
        ("1.1.5", "1.1.12", -1),
        ("2.0.0", "1.99.99", 1),
        ("1.0.0rc1", "1.0.0", -1),
        ("1.2.3-foo", "1.2.3-bar", 0),  # non-PEP440 falls back to numeric segments
    ],
)
def test_compare(a, b, expected):
    assert compare_versions(a, b) == expected


def test_helpers():
    assert versions_equal("v2.32.0", "2.32.0")
    assert is_less_than("1.1.5", "1.1.12")
    assert not is_less_than("1.1.12", "1.1.12")
