import requests

GITHUB_TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = "demo-service"
    return session
