"""CODEOWNERS parsing with GitHub semantics (gitignore-style patterns, last match wins)."""

from __future__ import annotations

import re
from dataclasses import dataclass

CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _compile(pattern: str) -> re.Pattern[str]:
    """Translate a CODEOWNERS pattern into a regex over repo-relative POSIX paths."""
    dir_only = pattern.endswith("/")
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    body = pattern.strip("/")
    out: list[str] = []
    i = 0
    while i < len(body):
        if body.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif body.startswith("/**", i) and i + 3 == len(body):
            out.append("/.*")
            i += 3
        elif body.startswith("**", i):
            out.append(".*")
            i += 2
        elif body[i] == "*":
            out.append("[^/]*")
            i += 1
        elif body[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(body[i]))
            i += 1
    prefix = "" if anchored else "(?:.*/)?"
    suffix = "/.*" if dir_only else "(?:/.*)?"
    return re.compile(f"^{prefix}{''.join(out)}{suffix}$")


@dataclass(frozen=True)
class Rule:
    """One CODEOWNERS line."""

    pattern: str
    owners: tuple[str, ...]
    regex: re.Pattern[str]


class CodeOwners:
    """Parsed CODEOWNERS file."""

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = rules

    @classmethod
    def parse(cls, text: str) -> CodeOwners:
        """Parse file content; comments, blank lines and rules without owners are ignored."""
        rules: list[Rule] = []
        for raw in text.splitlines():
            line = raw.split(" #", 1)[0].strip() if " #" in raw else raw.strip()
            if not line or line.startswith("#"):
                continue
            pattern, *owners = line.split()
            owners = [o for o in owners if o.startswith("@") or _EMAIL.match(o)]
            if owners:
                rules.append(Rule(pattern, tuple(owners), _compile(pattern)))
        return cls(rules)

    def owners_for(self, path: str) -> list[str]:
        """Owners of ``path`` (the last matching rule wins; empty if none match)."""
        norm = path.lstrip("/")
        for rule in reversed(self.rules):
            if rule.regex.match(norm):
                return list(rule.owners)
        return []

    def owners_for_paths(self, paths: list[str]) -> list[str]:
        """Union of owners across ``paths``, first-seen order, de-duplicated case-insensitively."""
        seen: dict[str, str] = {}
        for path in paths:
            for owner in self.owners_for(path):
                seen.setdefault(owner.lower(), owner)
        return list(seen.values())


def split_owners(owners: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Split owners into ``(users, teams, emails)``; users have no ``@``, teams are ``org/slug``."""
    users: list[str] = []
    teams: list[str] = []
    emails: list[str] = []
    for owner in owners:
        if owner.startswith("@"):
            handle = owner[1:]
            (teams if "/" in handle else users).append(handle)
        else:
            emails.append(owner)
    return users, teams, emails
