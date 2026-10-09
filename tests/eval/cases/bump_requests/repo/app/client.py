import requests

DEFAULT_TIMEOUT = 5.0


def make_session() -> requests.Session:
    """Session with the service's default headers."""
    session = requests.Session()
    session.headers["User-Agent"] = "demo-service"
    return session


def fetch_json(session: requests.Session, url: str) -> dict:
    return session.get(url, timeout=DEFAULT_TIMEOUT).json()
