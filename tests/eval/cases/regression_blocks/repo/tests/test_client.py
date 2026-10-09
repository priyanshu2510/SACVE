from app.client import make_session


def test_default_headers():
    assert make_session().headers["User-Agent"] == "demo-service"


def test_runs_against_the_pinned_release():
    import requests

    assert requests.__version__ == "2.31.0"  # an (unusually strict) test that any upgrade breaks
