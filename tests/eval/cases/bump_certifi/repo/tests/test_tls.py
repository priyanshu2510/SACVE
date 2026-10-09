import os

from app.tls import ca_bundle_path


def test_bundle_exists():
    assert os.path.isfile(ca_bundle_path())
