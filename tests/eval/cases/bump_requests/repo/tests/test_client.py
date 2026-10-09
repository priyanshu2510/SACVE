from app.client import make_session


def test_default_headers():
    assert make_session().headers["User-Agent"] == "demo-service"
