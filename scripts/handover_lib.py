"""HTML helpers and live fact extraction for the hand-over document."""

from __future__ import annotations

import html
import importlib.metadata as md
import inspect
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------------------------- html helpers
def esc(value: Any) -> str:
    """HTML-escape any value."""
    return html.escape(str(value), quote=True)


def code(text: str) -> str:
    return f"<code>{esc(text)}</code>"


def chip(kind: str, label: str | None = None) -> str:
    labels = {"done": "Done", "partial": "Partial", "todo": "Not built", "info": "Note", "p0": "P0", "p1": "P1", "p2": "P2"}
    return f'<span class="chip {kind}">{esc(label or labels[kind])}</span>'


def pre(text: str) -> str:
    return f"<pre><code>{esc(text.strip(chr(10)))}</code></pre>"


def callout(kind: str, title: str, body: str) -> str:
    """kind: '' (neutral) | warn | risk | ok. ``body`` is trusted HTML."""
    return f'<div class="callout {kind}"><b>{esc(title)}</b>{body}</div>'


def table(headers: list[str], rows: list[list[str]], *, raw: bool = True, compact: bool = False, num_cols: set[int] = frozenset(), table_id: str = "") -> str:
    """Render a table. With ``raw=True`` cells are trusted HTML; otherwise they are escaped."""
    cell = (lambda c: str(c)) if raw else (lambda c: esc(c))
    head = "".join(f'<th class="{"num" if i in num_cols else ""}">{esc(h)}</th>' for i, h in enumerate(headers))
    body = "".join("<tr>" + "".join(f'<td class="{"num" if i in num_cols else ""}">{cell(c)}</td>' for i, c in enumerate(r)) + "</tr>" for r in rows)
    idattr = f' id="{table_id}"' if table_id else ""
    return f'<div class="tablewrap{" compact" if compact else ""}"><table{idattr}><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def flow(nodes: list[tuple[str, str]]) -> str:
    """A horizontal chain. Each node is ``(label, kind)`` with kind '' | io | sb (runs in the sandbox)."""
    parts = []
    for i, (label, kind) in enumerate(nodes):
        if i:
            parts.append('<span class="ar">→</span>')
        parts.append(f'<span class="n {kind}">{esc(label)}</span>')
    return f'<div class="flow">{"".join(parts)}</div>'


def section(sec_id: str, title: str, body: str) -> str:
    return f'<section id="{sec_id}"><h2>{esc(title)}</h2>{body}</section>'


def boxes(items: list[tuple[str, str]]) -> str:
    return '<div class="boxes">' + "".join(f"<div class=\"box\"><b>{esc(t)}</b><span>{esc(s)}</span></div>" for t, s in items) + "</div>"


def layer(title: str, items: list[tuple[str, str]]) -> str:
    return f'<div class="layer"><h5>{esc(title)}</h5>{boxes(items)}</div>'


def ul(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"


# --------------------------------------------------------------------------------------------- live facts
def _collect_count(path: str, marker: str = "") -> int:
    out = subprocess.run([sys.executable, "-m", "pytest", "--collect-only", "-q", "-m", marker, path], cwd=ROOT, capture_output=True, text=True).stdout
    m = re.search(r"(\d+) tests? collected", out) or re.search(r"(\d+)/\d+ tests collected", out)
    return int(m.group(1)) if m else 0


def gather() -> dict[str, Any]:
    """Collect every fact that can drift from the real code."""
    sys.path.insert(0, str(ROOT))
    from src.api.main import create_app
    from src.core.config import Settings
    from src.core.database import Base
    import src.models  # noqa: F401
    from src.models.audit import EventType
    from src.models.job import JobStatus
    from src.agent import routing
    from src.workers.celery_app import celery_app
    import src.workers.tasks.audit_tasks, src.workers.tasks.notification_tasks, src.workers.tasks.remediation_tasks, src.workers.tasks.scan_tasks  # noqa: F401,E401

    facts: dict[str, Any] = {}
    py = lambda root: sum(len(p.read_text(errors="ignore").splitlines()) for p in (ROOT / root).rglob("*.py") if "__pycache__" not in p.parts and "cases" not in p.parts)  # noqa: E731
    facts["loc_src"], facts["loc_tests"] = py("src"), py("tests")
    facts["test_counts"] = {d: _collect_count(f"tests/{d}") for d in ("unit", "integration", "contract", "eval")}

    settings = []
    for name, f in Settings.model_fields.items():
        secret = "SecretStr" in str(f.annotation)
        default = "—" if secret else repr(f.default)
        settings.append({"name": name, "type": re.sub(r"typing\.|pydantic\.types\.|<class |>|'", "", str(f.annotation)).replace(" | None", "?"), "default": default, "secret": secret})
    facts["settings"] = settings

    routes = []
    for path, ops in sorted(create_app().openapi()["paths"].items()):
        for method, op in ops.items():
            routes.append({"method": method.upper(), "path": path, "summary": (op.get("summary") or "").strip()})
    facts["routes"] = routes

    tasks = []
    for name in sorted(t for t in celery_app.tasks if not t.startswith("celery.")):
        queue = celery_app.amqp.router.route({}, name)["queue"].name
        task = celery_app.tasks[name]
        tasks.append({"name": name, "queue": queue, "doc": (inspect.getdoc(task.run) or "").split("\n")[0], "retries": getattr(task, "max_retries", None)})
    facts["tasks"] = tasks
    facts["beat"] = [{"entry": k, "task": v["task"], "schedule": str(v["schedule"]).replace("<crontab: ", "").replace(" (m/h/dM/MY/d)>", "")} for k, v in celery_app.conf.beat_schedule.items()]
    facts["queues"] = sorted(q.name for q in celery_app.conf.task_queues)

    tables = {}
    for t in Base.metadata.sorted_tables:
        tables[t.name] = [(c.name, str(c.type).split("(")[0], "PK" if c.primary_key else ("FK" if c.foreign_keys else "")) for c in t.columns]
    facts["tables"] = tables
    facts["event_types"] = [e.value for e in EventType]
    facts["job_statuses"] = [s.value for s in JobStatus]
    facts["routers"] = [(n, (inspect.getdoc(f) or "").split("\n")[0]) for n, f in inspect.getmembers(routing, inspect.isfunction) if n.startswith("route_")]

    names = ["langgraph", "langgraph-checkpoint-postgres", "celery", "fastapi", "uvicorn", "pydantic", "pydantic-settings", "sqlalchemy", "alembic", "asyncpg", "psycopg", "httpx", "PyGithub", "docker", "redis", "boto3", "structlog", "pytest", "pytest-asyncio", "jsonschema"]
    facts["versions"] = {n: md.version(n) for n in names}
    facts["python"] = ".".join(map(str, sys.version_info[:3]))

    report = ROOT / "eval-report.json"
    facts["eval"] = json.loads(report.read_text()) if report.exists() else None
    return facts
