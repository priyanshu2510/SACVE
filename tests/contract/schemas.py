"""JSON Schemas of the external APIs we talk to (the *consumer contract*: what we send and what we rely on receiving).

Sources: OpenAI chat-completions reference (the assumed internal LLM contract), PagerDuty Events API v2, Atlassian Cloud
REST v3 (JIRA) and Confluence REST v1 documentation, GitHub REST API reference. The Teams API schema is our *assumption*
of the internal service: when the real schema differs, change it here first and the tests show what else must change.
"""

from __future__ import annotations

from typing import Any

import jsonschema

SHA = {"type": "string", "pattern": "^[0-9a-f]{40}$"}
NONEMPTY = {"type": "string", "minLength": 1}


def assert_valid(schema: dict[str, Any], instance: Any) -> None:
    """Validate with a readable failure message (draft 2020-12, formats checked)."""
    validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.absolute_path))
    assert not errors, "contract violation:\n" + "\n".join(f"  at /{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in errors)


# ------------------------------------------------------------------------------------------------ LLM (OpenAI-compatible)
LLM_REQUEST = {
    "type": "object",
    "required": ["model", "messages"],
    "properties": {
        "model": NONEMPTY,
        "messages": {"type": "array", "minItems": 1, "items": {
            "type": "object", "required": ["role", "content"], "additionalProperties": False,
            "properties": {"role": {"enum": ["system", "user", "assistant", "tool"]}, "content": {"type": "string"}}}},
        "max_tokens": {"type": "integer", "minimum": 1},
        "temperature": {"type": "number", "minimum": 0, "maximum": 2},
        "response_format": {"type": "object", "required": ["type"], "properties": {"type": {"enum": ["text", "json_object", "json_schema"]}}},
    },
    "additionalProperties": False,
}
LLM_RESPONSE = {
    "type": "object",
    "required": ["choices"],
    "properties": {
        "choices": {"type": "array", "minItems": 1, "items": {
            "type": "object", "required": ["message"],
            "properties": {"message": {"type": "object", "required": ["role", "content"],
                                       "properties": {"role": {"const": "assistant"}, "content": {"type": ["string", "null"]}}}}}},
        "usage": {"type": "object"},
    },
}

# ------------------------------------------------------------------------------------------------ Teams (our assumption)
TEAMS_REQUEST = {
    "type": "object",
    "required": ["recipients", "subject", "body", "severity", "metadata"],
    "additionalProperties": False,
    "properties": {
        "recipients": {"type": "array", "minItems": 1, "items": NONEMPTY},
        "subject": {"type": "string", "minLength": 1, "maxLength": 500},
        "body": NONEMPTY,
        "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "metadata": {"type": "object", "required": ["cve_id"], "properties": {"cve_id": {"type": "string", "pattern": "^CVE-\\d{4}-\\d{4,}$"}}},
    },
}

# ------------------------------------------------------------------------------------------------ PagerDuty Events API v2
PAGERDUTY_REQUEST = {
    "type": "object",
    "required": ["routing_key", "event_action", "payload"],
    "properties": {
        "routing_key": NONEMPTY,
        "event_action": {"enum": ["trigger", "acknowledge", "resolve"]},
        "dedup_key": {"type": "string", "maxLength": 255},
        "payload": {"type": "object", "required": ["summary", "source", "severity"], "properties": {
            "summary": {"type": "string", "minLength": 1, "maxLength": 1024}, "source": NONEMPTY,
            "severity": {"enum": ["critical", "error", "warning", "info"]}, "custom_details": {"type": "object"}}},
    },
}

# ------------------------------------------------------------------------------------------------ Atlassian Document Format (JIRA v3)
ADF_TEXT = {"type": "object", "required": ["type", "text"], "properties": {
    "type": {"const": "text"}, "text": {"type": "string", "minLength": 1},
    "marks": {"type": "array", "items": {"type": "object", "required": ["type"], "properties": {
        "type": {"enum": ["link", "strong", "em", "code"]},
        "attrs": {"type": "object", "properties": {"href": {"type": "string", "pattern": "^https?://"}}}}}}}}
ADF_PARAGRAPH = {"type": "object", "required": ["type", "content"], "properties": {"type": {"const": "paragraph"}, "content": {"type": "array", "items": ADF_TEXT}}}
ADF_DOC = {"type": "object", "required": ["type", "version", "content"], "properties": {
    "type": {"const": "doc"}, "version": {"const": 1}, "content": {"type": "array", "items": ADF_PARAGRAPH}}}

JIRA_CREATE_ISSUE = {
    "type": "object", "required": ["fields"], "additionalProperties": False,
    "properties": {"fields": {"type": "object", "required": ["project", "issuetype", "summary"], "properties": {
        "project": {"type": "object", "required": ["key"], "properties": {"key": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]+$"}}},
        "issuetype": {"type": "object", "required": ["name"], "properties": {"name": NONEMPTY}},
        "summary": {"type": "string", "minLength": 1, "maxLength": 255, "pattern": "^[^\\n\\r]+$"},
        "description": ADF_DOC,
        "priority": {"type": "object", "required": ["name"], "properties": {"name": NONEMPTY}},
        "labels": {"type": "array", "items": {"type": "string", "pattern": "^\\S+$"}},  # JIRA labels cannot contain whitespace
        "assignee": {"type": "object", "required": ["accountId"], "properties": {"accountId": NONEMPTY}},
    }}},
}
JIRA_UPDATE_DESCRIPTION = {"type": "object", "required": ["fields"], "properties": {"fields": {"type": "object", "required": ["description"], "properties": {"description": ADF_DOC}}}}
JIRA_COMMENT = {"type": "object", "required": ["body"], "properties": {"body": ADF_DOC}}
JIRA_TRANSITION = {"type": "object", "required": ["transition"], "properties": {"transition": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string", "pattern": "^\\d+$"}}}}}
JIRA_ASSIGNEE = {"type": "object", "required": ["accountId"], "properties": {"accountId": NONEMPTY}}
JIRA_SEARCH_JQL = {"type": "object", "required": ["jql"], "properties": {"jql": NONEMPTY, "fields": {"type": "array", "items": {"type": "string"}}, "maxResults": {"type": "integer", "minimum": 1, "maximum": 5000}}}

# Responses we depend on
JIRA_CREATE_RESPONSE = {"type": "object", "required": ["id", "key"], "properties": {"key": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]+-\\d+$"}}}
JIRA_TRANSITIONS_RESPONSE = {"type": "object", "required": ["transitions"], "properties": {"transitions": {"type": "array", "items": {
    "type": "object", "required": ["id", "name"], "properties": {"id": NONEMPTY, "name": NONEMPTY, "to": {"type": "object", "properties": {"name": NONEMPTY}}}}}}}
JIRA_SEARCH_RESPONSE = {"type": "object", "required": ["issues"], "properties": {"issues": {"type": "array", "items": {"type": "object", "required": ["key"]}}}}

# ------------------------------------------------------------------------------------------------ Confluence REST v1
CONFLUENCE_BODY = {"type": "object", "required": ["storage"], "properties": {"storage": {
    "type": "object", "required": ["value", "representation"], "properties": {"value": {"type": "string"}, "representation": {"const": "storage"}}}}}
CONFLUENCE_CREATE = {"type": "object", "required": ["type", "title", "space", "body"], "properties": {
    "type": {"const": "page"}, "title": {"type": "string", "minLength": 1, "maxLength": 255},
    "space": {"type": "object", "required": ["key"], "properties": {"key": NONEMPTY}},
    "ancestors": {"type": "array", "minItems": 1, "maxItems": 1, "items": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string", "pattern": "^\\d+$"}}}},  # ids are strings
    "body": CONFLUENCE_BODY}}
CONFLUENCE_UPDATE = {"type": "object", "required": ["type", "title", "version", "body"], "properties": {
    "type": {"const": "page"}, "title": NONEMPTY, "version": {"type": "object", "required": ["number"], "properties": {"number": {"type": "integer", "minimum": 2}}},
    "body": CONFLUENCE_BODY}}
CONFLUENCE_PAGE_RESPONSE = {"type": "object", "required": ["id", "title", "_links"], "properties": {
    "id": NONEMPTY, "_links": {"type": "object", "required": ["webui"], "properties": {"webui": {"type": "string"}, "base": {"type": "string"}}}}}
CONFLUENCE_SEARCH_RESPONSE = {"type": "object", "required": ["results"], "properties": {"results": {"type": "array", "items": {
    "type": "object", "required": ["id", "version"], "properties": {"version": {"type": "object", "required": ["number"], "properties": {"number": {"type": "integer"}}}}}}}}

# ------------------------------------------------------------------------------------------------ GitHub REST (request bodies)
GH_TREE_ELEMENT = {"type": "object", "required": ["path", "mode", "type"], "properties": {
    "path": {"type": "string", "minLength": 1, "pattern": "^[^/].*[^/]$"}, "mode": {"enum": ["100644", "100755", "040000", "160000", "120000"]},
    "type": {"enum": ["blob", "tree", "commit"]}, "content": {"type": "string"}, "sha": SHA}}
GH_CREATE_TREE = {"type": "object", "required": ["tree"], "properties": {"base_tree": SHA, "tree": {"type": "array", "minItems": 1, "items": GH_TREE_ELEMENT}}}
GH_CREATE_COMMIT = {"type": "object", "required": ["message", "tree", "parents"], "properties": {"message": NONEMPTY, "tree": SHA, "parents": {"type": "array", "items": SHA}}}
GH_CREATE_REF = {"type": "object", "required": ["ref", "sha"], "properties": {"ref": {"type": "string", "pattern": "^refs/heads/[^\\s~^:?*\\[\\\\]+$"}, "sha": SHA}}
GH_CREATE_PULL = {"type": "object", "required": ["title", "head", "base"], "properties": {"title": NONEMPTY, "body": {"type": "string", "maxLength": 65536}, "head": NONEMPTY, "base": NONEMPTY}}
GH_ADD_LABELS = {"oneOf": [
    {"type": "object", "required": ["labels"], "properties": {"labels": {"type": "array", "minItems": 1, "items": NONEMPTY}}},
    {"type": "array", "minItems": 1, "items": NONEMPTY}]}
GH_CREATE_LABEL = {"type": "object", "required": ["name", "color"], "properties": {"name": NONEMPTY, "color": {"type": "string", "pattern": "^[0-9a-fA-F]{6}$"}}}
GH_REVIEW_REQUEST = {"type": "object", "minProperties": 1, "properties": {
    "reviewers": {"type": "array", "items": NONEMPTY}, "team_reviewers": {"type": "array", "items": {"type": "string", "pattern": "^[^/\\s]+$"}}},  # team slug, not org/slug
    "additionalProperties": False}
