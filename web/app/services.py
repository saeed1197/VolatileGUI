"""Shared query/aggregation helpers used by both routers."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import catalog, config, runner_client, triage
from .models import Batch, Case, Evidence, Finding, Job, Report

SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._\- ]+")


def available_plugins(engine: str, force: bool = False) -> Dict[str, dict]:
    discovered = runner_client.plugins(engine, force=force)
    return catalog.merge_discovered(engine, discovered)


def os_for(ev: Optional[Evidence]) -> str:
    if ev and ev.detected_os:
        return ev.detected_os
    return "windows"


CRASH_DUMP_EXTS = {".dmp", ".mdmp"}


def is_windows_crash_dump(ev: Optional[Evidence]) -> bool:
    """Whether the image looks like a crash dump rather than a raw memory image.

    windows.crashinfo only works against real crash dumps (BSOD / LiveKd), and
    fails with a confusing traceback on ordinary raw/VMware images.
    """
    if not ev:
        return False
    ext = os.path.splitext(ev.filename or "")[1].lower()
    return ext in CRASH_DUMP_EXTS


def safe_filename(name: str) -> str:
    name = os.path.basename(name or "image.raw")
    name = SAFE_NAME_RE.sub("_", name).strip() or "image.raw"
    return name[:180]


def unique_evidence_path(filename: str):
    base = config.EVIDENCE_DIR / filename
    if not base.exists():
        return base
    stem, ext = os.path.splitext(filename)
    i = 2
    while True:
        cand = config.EVIDENCE_DIR / f"{stem}-{i}{ext}"
        if not cand.exists():
            return cand
        i += 1


def runner_path(local_path) -> str:
    """The path as the runner containers see it (shared /evidence mount)."""
    return "/evidence/" + os.path.basename(str(local_path))


# ---------------------------------------------------------------------------
# aggregations
# ---------------------------------------------------------------------------
def evidence_rollup(s: Session, evidence_id: int) -> Dict[str, Any]:
    jobs = list(s.scalars(select(Job).where(Job.evidence_id == evidence_id)))
    findings = list(s.scalars(
        select(Finding).where(Finding.evidence_id == evidence_id)))
    counts: Dict[str, int] = {}
    for f in findings:
        if f.state != "dismissed":
            counts[f.severity] = counts.get(f.severity, 0) + 1
    score = triage.risk_score(findings)
    by_status: Dict[str, int] = {}
    for j in jobs:
        by_status[j.status] = by_status.get(j.status, 0) + 1
    return {
        "jobs": len(jobs),
        "by_status": by_status,
        "running": by_status.get("running", 0) + by_status.get("queued", 0),
        "rows": sum(j.row_count or 0 for j in jobs),
        "runtime": sum(j.duration or 0 for j in jobs),
        "findings": len([f for f in findings if f.state != "dismissed"]),
        "severity_counts": counts,
        "risk_score": score,
        "risk_band": triage.risk_band(score),
        "engines": sorted({j.engine for j in jobs}),
        "last_run": max([j.created_at for j in jobs], default=None),
    }


def dashboard(s: Session) -> Dict[str, Any]:
    total_evidence = s.scalar(select(func.count()).select_from(Evidence)) or 0
    total_jobs = s.scalar(select(func.count()).select_from(Job)) or 0
    total_findings = s.scalar(
        select(func.count()).select_from(Finding).where(Finding.state != "dismissed")) or 0
    total_rows = s.scalar(select(func.coalesce(func.sum(Job.row_count), 0))) or 0
    runtime = s.scalar(select(func.coalesce(func.sum(Job.duration), 0.0))) or 0.0

    by_status = dict(s.execute(
        select(Job.status, func.count()).group_by(Job.status)).all())
    by_engine = dict(s.execute(
        select(Job.engine, func.count()).group_by(Job.engine)).all())
    by_severity = dict(s.execute(
        select(Finding.severity, func.count())
        .where(Finding.state != "dismissed")
        .group_by(Finding.severity)).all())

    recent_jobs = list(s.scalars(
        select(Job).order_by(Job.created_at.desc()).limit(12)))
    recent_evidence = list(s.scalars(
        select(Evidence).order_by(Evidence.created_at.desc()).limit(6)))
    top_findings = list(s.scalars(
        select(Finding).where(Finding.state != "dismissed")
        .order_by(Finding.score.desc(), Finding.id.desc()).limit(10)))

    top_plugins = s.execute(
        select(Job.plugin_label, Job.engine, func.count())
        .group_by(Job.plugin_label, Job.engine)
        .order_by(func.count().desc()).limit(8)).all()

    return {
        "total_evidence": total_evidence,
        "total_jobs": total_jobs,
        "total_findings": total_findings,
        "total_rows": total_rows,
        "runtime": runtime,
        "by_status": by_status,
        "by_engine": by_engine,
        "by_severity": by_severity,
        "recent_jobs": recent_jobs,
        "recent_evidence": recent_evidence,
        "top_findings": top_findings,
        "top_plugins": [{"label": r[0], "engine": r[1], "count": r[2]}
                        for r in top_plugins],
        "evidence_map": {e.id: e for e in s.scalars(select(Evidence))},
    }


def evidence_map(s: Session) -> Dict[int, Evidence]:
    return {e.id: e for e in s.scalars(select(Evidence))}


def scan_evidence_dir(s: Session) -> List[Evidence]:
    """Register any new image files dropped into the evidence folder."""
    known = {os.path.basename(p) for p in
             s.scalars(select(Evidence.path))}
    added: List[Evidence] = []
    for entry in sorted(config.EVIDENCE_DIR.iterdir()):
        if not entry.is_file():
            continue
        if entry.name.startswith(".") or entry.name in known:
            continue
        if entry.suffix.lower() not in config.IMAGE_SUFFIXES and entry.stat().st_size < (
                64 * 1024 * 1024):
            continue
        ev = Evidence(
            name=entry.stem,
            filename=entry.name,
            path=runner_path(entry),
            size=entry.stat().st_size,
            source="scan",
        )
        s.add(ev)
        added.append(ev)
    s.flush()
    return added


def paginate(rows: List[Any], page: int, per_page: int) -> Dict[str, Any]:
    total = len(rows)
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    return {
        "items": rows[start:start + per_page],
        "page": page,
        "pages": pages,
        "total": total,
        "per_page": per_page,
        "has_prev": page > 1,
        "has_next": page < pages,
        "start": start + 1 if total else 0,
        "end": min(start + per_page, total),
    }


def filter_sort_rows(columns: List[str], rows: List[list], q: str = "",
                     sort: str = "", direction: str = "asc") -> List[list]:
    out = rows
    if q:
        needle = q.lower()
        out = [r for r in out
               if any(needle in str(v).lower() for v in r)]
    if sort and sort in columns:
        idx = columns.index(sort)

        def key(row):
            value = row[idx] if idx < len(row) else ""
            try:
                return (0, float(value))
            except Exception:
                return (1, str(value).lower())

        out = sorted(out, key=key, reverse=(direction == "desc"))
    return out
