import requests


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = "demo-service"
    return session
