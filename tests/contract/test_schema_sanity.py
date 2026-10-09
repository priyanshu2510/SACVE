"""The contract schemas must have teeth: known-bad payloads must be rejected."""

import pytest

from tests.contract import schemas as S

ADF = {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": "x"}]}]}
GOOD_ISSUE = {"fields": {"project": {"key": "SEC"}, "issuetype": {"name": "Task"}, "summary": "s", "description": ADF, "labels": ["a-b"]}}


def bad(schema, instance):
    with pytest.raises(AssertionError, match="contract violation"):
        S.assert_valid(schema, instance)


def mutate(base, path, value):
    import copy

    out = copy.deepcopy(base)
    node = out
    for key in path[:-1]:
        node = node[key]
    if value is ...:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return out


def test_good_baselines_are_valid():
    S.assert_valid(S.JIRA_CREATE_ISSUE, GOOD_ISSUE)


@pytest.mark.parametrize(
    "path,value",
    [(("fields", "summary"), "line1\nline2"), (("fields", "summary"), "x" * 256), (("fields", "labels"), ["has space"]), (("fields", "description"), "plain string"),
     (("fields", "project", "key"), "lower"), (("fields", "description", "version"), 2), (("fields", "issuetype"), ...), (("fields", "assignee"), {"id": "x"})],
)  # fmt: skip
def test_jira_create_rejects(path, value):
    bad(S.JIRA_CREATE_ISSUE, mutate(GOOD_ISSUE, path, value))


def test_adf_rejects_non_http_links():
    link = {"type": "text", "text": "x", "marks": [{"type": "link", "attrs": {"href": "javascript:alert(1)"}}]}
    bad(S.ADF_DOC, {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [link]}]})


def test_llm_request_rejects():
    ok = {"model": "m", "messages": [{"role": "user", "content": "x"}]}
    S.assert_valid(S.LLM_REQUEST, ok)
    for broken in [{**ok, "messages": []}, {**ok, "messages": [{"role": "robot", "content": "x"}]}, {**ok, "temperature": 5}, {**ok, "extra": 1},
                   {**ok, "messages": [{"role": "user", "content": None}]}, {"messages": ok["messages"]}]:  # fmt: skip
        bad(S.LLM_REQUEST, broken)


def test_pagerduty_and_teams_reject():
    pd = {"routing_key": "k", "event_action": "trigger", "payload": {"summary": "s", "source": "x", "severity": "critical"}}
    S.assert_valid(S.PAGERDUTY_REQUEST, pd)
    bad(S.PAGERDUTY_REQUEST, mutate(pd, ("payload", "severity"), "HIGH"))
    bad(S.PAGERDUTY_REQUEST, mutate(pd, ("payload", "summary"), "x" * 1025))
    bad(S.PAGERDUTY_REQUEST, mutate(pd, ("event_action",), "page"))
    teams = {"recipients": ["a@b.c"], "subject": "s", "body": "b", "severity": "HIGH", "metadata": {"cve_id": "CVE-2024-1234"}}
    S.assert_valid(S.TEAMS_REQUEST, teams)
    bad(S.TEAMS_REQUEST, mutate(teams, ("recipients",), []))
    bad(S.TEAMS_REQUEST, mutate(teams, ("metadata", "cve_id"), "nope"))


def test_confluence_rejects():
    page = {"type": "page", "title": "t", "space": {"key": "SEC"}, "ancestors": [{"id": "123"}], "body": {"storage": {"value": "<p/>", "representation": "storage"}}}
    S.assert_valid(S.CONFLUENCE_CREATE, page)
    bad(S.CONFLUENCE_CREATE, mutate(page, ("ancestors", 0, "id"), 123))  # ids must be strings
    bad(S.CONFLUENCE_CREATE, mutate(page, ("body", "storage", "representation"), "wiki"))
    bad(S.CONFLUENCE_UPDATE, {"type": "page", "title": "t", "version": {"number": 1}, "body": page["body"]})  # an update must bump the version


def test_github_schemas_reject():
    sha = "a" * 40
    S.assert_valid(S.GH_CREATE_REF, {"ref": "refs/heads/fix/x", "sha": sha})
    bad(S.GH_CREATE_REF, {"ref": "fix/x", "sha": sha})
    bad(S.GH_CREATE_REF, {"ref": "refs/heads/has space", "sha": sha})
    bad(S.GH_CREATE_COMMIT, {"message": "m", "tree": "short", "parents": [sha]})
    bad(S.GH_CREATE_TREE, {"tree": [{"path": "a", "mode": "100666", "type": "blob", "content": "x"}]})
    bad(S.GH_REVIEW_REQUEST, {"team_reviewers": ["org/platform"]})  # must be the slug only
    bad(S.GH_REVIEW_REQUEST, {})
    bad(S.GH_CREATE_LABEL, {"name": "x", "color": "#ff0000"})  # no leading '#'
