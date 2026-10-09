import pytest

from src.agent.deps import fixed_versions_from_ranges
from src.utils.packages import declared_in_manifest, import_names, normalise_pip_name


def test_normalise_pip_name():
    assert normalise_pip_name("Foo_Bar.baz") == "foo-bar-baz"


@pytest.mark.parametrize(
    "eco,pkg,expected",
    [("pip", "requests", ["requests"]), ("pip", "PyYAML", ["yaml", "pyyaml"]), ("pip", "scikit-learn", ["sklearn", "scikit_learn"]),
     ("pip", "my-lib", ["my_lib"]), ("maven", "org.apache.logging.log4j:log4j-core", ["org.apache.logging.log4j"]),
     ("npm", "left-pad", ["left-pad"]), ("go", "github.com/x/y", ["github.com/x/y"])],
)  # fmt: skip
def test_import_names(eco, pkg, expected):
    assert import_names(eco, pkg) == expected


@pytest.mark.parametrize(
    "manifest,pkg,expected",
    [
        ("requests==2.31.0\n", "requests", True),
        ("Requests>=2.0\n", "requests", True),
        ("flask\nrequests[security]==2.0\n", "requests", True),
        ("  requests ; python_version>'3'\n", "requests", True),
        ('dependencies = ["requests>=2", "flask"]\n', "requests", True),
        ("requests-toolbelt==1.0\n", "requests", False),
        ("# requests is great\nflask==3\n", "requests", False),
        ("python_dateutil==2.8\n", "python-dateutil", True),
        ("", "requests", False),
    ],
)
def test_declared_in_manifest(manifest, pkg, expected):
    assert declared_in_manifest(manifest, pkg) is expected


def test_fixed_versions_from_ranges():
    assert fixed_versions_from_ranges(["< 1.4.9", ">= 2.0.0, < 2.0.3", ">= 3.0.0, <= 3.1.0"], "1.4.9") == ["1.4.9", "2.0.3"]
    assert fixed_versions_from_ranges([], None) == []
    assert fixed_versions_from_ranges(["all versions"], "1.2.3") == ["1.2.3"]
