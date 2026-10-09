import pytest

from src.services.github.codeowners import CodeOwners, split_owners

SAMPLE = """
# comment line
*                       @org/everyone
*.js                    @frontend
/docs/                  @docs-team   # trailing comment
docs/internal/**        @sec-team alice@corp.com
/requirements*.txt      @python-owners
apps/*/config           @cfg-owner
src/**/generated/       @nobody-reviews
/build/logs/
/no-owner-line-ignored-because-empty
"""


@pytest.fixture
def co():
    return CodeOwners.parse(SAMPLE)


@pytest.mark.parametrize(
    "path,expected",
    [
        ("README.md", ["@org/everyone"]),  # catch-all
        ("web/app.js", ["@frontend"]),  # unanchored glob matches at any depth
        ("app.js", ["@frontend"]),
        ("docs/guide.md", ["@docs-team"]),  # anchored directory
        ("other/docs/guide.md", ["@org/everyone"]),  # /docs/ is anchored to root
        ("docs/internal/a/b.md", ["@sec-team", "alice@corp.com"]),  # later rule wins; email owner kept
        ("requirements.txt", ["@python-owners"]),
        ("requirements-dev.txt", ["@python-owners"]),
        ("sub/requirements.txt", ["@org/everyone"]),  # anchored: not in subdirs
        ("apps/api/config", ["@cfg-owner"]),
        ("apps/api/config/x.yml", ["@cfg-owner"]),  # directory contents
        ("apps/api/v2/config", ["@org/everyone"]),  # * does not cross /
        ("src/a/b/generated/x.py", ["@nobody-reviews"]),
        ("src/generated/x.py", ["@nobody-reviews"]),  # ** matches zero directories
        ("build/logs/x.log", ["@org/everyone"]),  # rule without owners is ignored
    ],
)
def test_owners_for(co, path, expected):
    assert co.owners_for(path) == expected


def test_no_match_without_catch_all():
    assert CodeOwners.parse("*.py @py").owners_for("README.md") == []
    assert CodeOwners.parse("").owners_for("x") == []


def test_owners_for_paths_dedupes_and_orders(co):
    got = co.owners_for_paths(["requirements.txt", "web/app.js", "README.md", "other.js", "x/Requirements.txt"])
    assert got == ["@python-owners", "@frontend", "@org/everyone"]


def test_leading_slash_on_query_path_is_ignored(co):
    assert co.owners_for("/docs/x.md") == ["@docs-team"]


def test_split_owners():
    users, teams, emails = split_owners(["@alice", "@org/platform", "bob@corp.com"])
    assert (users, teams, emails) == (["alice"], ["org/platform"], ["bob@corp.com"])
