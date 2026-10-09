"""Helpers for faking the OpenAI-compatible internal LLM API in tests."""

import json

import httpx


def good(**over):
    body = {
        "file_changes": [
            {
                "file_path": "requirements.txt",
                "change_description": "bump requests",
                "original_content": "requests==2.31.0",
                "new_content": "requests==2.32.0",
            }
        ],
        "explanation": "Bump requests to 2.32.0.",
        "breaking_change_risk": "low",
        "breaking_change_notes": None,
        "self_confidence": 90,
    }
    body.update(over)
    return body


def chat(content) -> httpx.Response:
    text = content if isinstance(content, str) else json.dumps(content)
    return httpx.Response(200, json={"choices": [{"message": {"content": text}}], "usage": {"total_tokens": 42}})


class Recorder:
    """MockTransport handler serving scripted responses and recording requests."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        item = self.responses[min(len(self.requests), len(self.responses)) - 1]
        return item(request) if callable(item) else item

    @property
    def bodies(self):
        return [json.loads(r.content) for r in self.requests]
