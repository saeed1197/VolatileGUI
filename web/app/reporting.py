"""Report generation: HTML, PDF, JSON, CSV and a full ZIP bundle."""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import zipfile
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import catalog, config, triage, worker
from .models import Case, Evidence, Finding, Job, Report, utcnow

MAX_REPORT_ROWS = 300          # rows per plugin table inside a rendered report


# ---------------------------------------------------------------------------
# context assembly
# ---------------------------------------------------------------------------
def build_context(s: Session, evidence_id: int,
                  job_ids: Optional[List[int]] = None,
                  include_empty: bool = False,
                  max_rows: int = MAX_REPORT_ROWS) -> Dict[str, Any]:
    ev = s.get(Evidence, evidence_id)
    if ev is None:
        raise ValueError("evidence not found")
    case = s.get(Case, ev.case_id) if ev.case_id else None

    q = select(Job).where(Job.evidence_id == evidence_id).order_by(Job.id)
    if job_ids:
        q = q.where(Job.id.in_(job_ids))
    jobs = list(s.scalars(q))
    if not include_empty:
        jobs = [j for j in jobs if j.status in ("success", "empty", "failed")]

    findings = list(s.scalars(
        select(Finding).where(Finding.evidence_id == evidence_id)
        .order_by(Finding.severity, Finding.id)))
    findings.sort(key=lambda f: f.rank)

    sections = []
    for job in jobs:
        data = worker.load_result(job.uid) or {}
        rows = data.get("rows") or []
        sections.append({
            "job": job,
            "meta": catalog.meta_of(job.engine, job.plugin),
            "columns": data.get("columns") or [],
            "rows": rows[:max_rows],
            "truncated": max(0, len(rows) - max_rows),
            "text": (data.get("text") or "")[:20000],
            "format": data.get("format", ""),
            "findings": [f for f in findings if f.job_id == job.id],
        })

    counts: Dict[str, int] = {}
    for f in findings:
        if f.state != "dismissed":
            counts[f.severity] = counts.get(f.severity, 0) + 1
    score = triage.risk_score(findings)

    return {
        "generated_at": utcnow(),
        "app": {"name": config.APP_NAME, "version": config.VERSION},
        "evidence": ev,
        "case": case,
        "jobs": jobs,
        "sections": sections,
        "findings": [f for f in findings if f.state != "dismissed"],
        "dismissed": [f for f in findings if f.state == "dismissed"],
        "severity_counts": counts,
        "risk_score": score,
        "risk_band": triage.risk_band(score),
        "stats": {
            "total_jobs": len(jobs),
            "successful": sum(1 for j in jobs if j.status == "success"),
            "failed": sum(1 for j in jobs if j.status == "failed"),
            "empty": sum(1 for j in jobs if j.status == "empty"),
            "rows": sum(j.row_count or 0 for j in jobs),
            "runtime": sum(j.duration or 0 for j in jobs),
            "engines": sorted({j.engine for j in jobs}),
        },
    }


# ---------------------------------------------------------------------------
# writers
# ---------------------------------------------------------------------------
def _slug(text: str) -> str:
    keep = [c if (c.isalnum() or c in "-_") else "-" for c in (text or "report")]
    return "".join(keep).strip("-").lower()[:60] or "report"


def _stamp() -> str:
    return dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def write_html(s: Session, evidence_id: int, html: str,
               title: str) -> Report:
    name = f"{_slug(title)}-{_stamp()}.html"
    path = config.REPORT_DIR / name
    path.write_text(html, encoding="utf-8")
    rep = Report(evidence_id=evidence_id, title=title, fmt="html",
                 path=str(path), size=path.stat().st_size)
    s.add(rep)
    s.flush()
    return rep


def write_pdf(s: Session, evidence_id: int, html: str, title: str) -> Report:
    try:
        from weasyprint import HTML  # imported lazily: heavy
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "PDF export needs WeasyPrint and its pango/cairo libraries. "
            f"Import failed: {exc}") from exc
    name = f"{_slug(title)}-{_stamp()}.pdf"
    path = config.REPORT_DIR / name
    HTML(string=html, base_url=str(config.REPORT_DIR)).write_pdf(str(path))
    rep = Report(evidence_id=evidence_id, title=title, fmt="pdf",
                 path=str(path), size=path.stat().st_size)
    s.add(rep)
    s.flush()
    return rep


def job_csv(job: Job) -> str:
    data = worker.load_result(job.uid) or {}
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    cols = data.get("columns") or []
    if cols:
        writer.writerow(cols)
        for row in data.get("rows") or []:
            writer.writerow(["" if v is None else v for v in row])
    else:
        writer.writerow(["output"])
        for line in (data.get("text") or "").splitlines():
            writer.writerow([line])
    return buf.getvalue()


def evidence_json(s: Session, evidence_id: int,
                  include_rows: bool = True) -> Dict[str, Any]:
    ctx = build_context(s, evidence_id, max_rows=10 ** 9 if include_rows else 0)
    ev: Evidence = ctx["evidence"]
    return {
        "generated_at": ctx["generated_at"].isoformat(),
        "platform": {"name": config.APP_NAME, "version": config.VERSION},
        "case": ({"id": ctx["case"].id, "name": ctx["case"].name}
                 if ctx["case"] else None),
        "evidence": {
            "id": ev.id, "name": ev.name, "filename": ev.filename,
            "path": ev.path, "size": ev.size, "md5": ev.md5,
            "sha256": ev.sha256, "detected_os": ev.detected_os,
            "vol2_profile": ev.vol2_profile, "notes": ev.notes,
            "created_at": ev.created_at.isoformat(),
        },
        "risk": {"score": ctx["risk_score"], "band": ctx["risk_band"],
                 "counts": ctx["severity_counts"]},
        "findings": [{
            "severity": f.severity, "category": f.category, "rule": f.rule_id,
            "title": f.title, "detail": f.detail,
            "recommendation": f.recommendation, "state": f.state,
            "context": f.context,
            "job": {"id": f.job_id},
        } for f in ctx["findings"]],
        "runs": [{
            "id": sec["job"].id,
            "uid": sec["job"].uid,
            "engine": sec["job"].engine,
            "plugin": sec["job"].plugin,
            "label": sec["job"].plugin_label,
            "profile": sec["job"].profile,
            "args": sec["job"].args,
            "status": sec["job"].status,
            "rc": sec["job"].rc,
            "duration": sec["job"].duration,
            "row_count": sec["job"].row_count,
            "command": sec["job"].command,
            "started_at": sec["job"].started_at.isoformat() if sec["job"].started_at else None,
            "columns": sec["columns"],
            "rows": sec["rows"] if include_rows else [],
            "text": sec["text"] if include_rows else "",
        } for sec in ctx["sections"]],
    }


def bundle_zip(s: Session, evidence_id: int, html: Optional[str] = None) -> Report:
    """Everything about one evidence item in a single archive."""
    ctx = build_context(s, evidence_id, max_rows=10 ** 9)
    ev: Evidence = ctx["evidence"]
    name = f"{_slug(ev.name)}-bundle-{_stamp()}.zip"
    path = config.REPORT_DIR / name

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("report.json", json.dumps(
            evidence_json(s, evidence_id), indent=2, default=str))
        if html:
            zf.writestr("report.html", html)
        findings_csv = io.StringIO()
        w = csv.writer(findings_csv, lineterminator="\n")
        w.writerow(["severity", "category", "rule", "title", "detail",
                    "recommendation", "state"])
        for f in ctx["findings"]:
            w.writerow([f.severity, f.category, f.rule_id, f.title,
                        f.detail.replace("\n", " ")[:2000], f.recommendation,
                        f.state])
        zf.writestr("findings.csv", findings_csv.getvalue())

        for sec in ctx["sections"]:
            job: Job = sec["job"]
            safe = _slug(f"{job.engine}-{job.plugin}-{job.id}")
            zf.writestr(f"results/{safe}.csv", job_csv(job))
            log = worker.read_log(job.uid)
            if log:
                zf.writestr(f"logs/{safe}.log", log)

        readme = (
            f"{config.APP_NAME} evidence bundle\n"
            f"{'=' * 60}\n"
            f"Evidence : {ev.name} ({ev.filename})\n"
            f"SHA-256  : {ev.sha256 or 'not computed'}\n"
            f"MD5      : {ev.md5 or 'not computed'}\n"
            f"Size     : {ev.size} bytes\n"
            f"OS       : {ev.detected_os or 'unknown'}\n"
            f"Profile  : {ev.vol2_profile or 'n/a'}\n"
            f"Generated: {ctx['generated_at']} UTC\n"
            f"Risk     : {ctx['risk_score']}/100 ({ctx['risk_band']})\n"
            f"Runs     : {ctx['stats']['total_jobs']}\n\n"
            "Contents:\n"
            "  report.json    full machine-readable export\n"
            "  report.html    rendered analyst report (if generated)\n"
            "  findings.csv   triage findings\n"
            "  results/*.csv  one file per plugin run\n"
            "  logs/*.log     raw execution logs\n"
        )
        zf.writestr("README.txt", readme)

    rep = Report(evidence_id=evidence_id, title=f"{ev.name} bundle", fmt="zip",
                 path=str(path), size=path.stat().st_size)
    s.add(rep)
    s.flush()
    return rep


# ---------------------------------------------------------------------------
# run comparison
# ---------------------------------------------------------------------------
def compare(job_a: Job, job_b: Job, key_columns: Optional[List[str]] = None
            ) -> Dict[str, Any]:
    """Diff two plugin runs. Rows are compared on a key, or whole-row."""
    a = worker.load_result(job_a.uid) or {}
    b = worker.load_result(job_b.uid) or {}
    cols_a = a.get("columns") or []
    cols_b = b.get("columns") or []
    common = [c for c in cols_a if c in cols_b] or cols_a or cols_b

    def keyed(data, cols):
        out = {}
        idx = {c: (data.get("columns") or []).index(c)
               for c in cols if c in (data.get("columns") or [])}
        for row in data.get("rows") or []:
            key = tuple(str(row[idx[c]]) if c in idx and idx[c] < len(row) else ""
                        for c in cols)
            out[key] = row
        return out

    key_cols = key_columns or common
    ka, kb = keyed(a, key_cols), keyed(b, key_cols)
    only_a = [ka[k] for k in ka.keys() - kb.keys()]
    only_b = [kb[k] for k in kb.keys() - ka.keys()]
    changed = []
    for k in ka.keys() & kb.keys():
        if ka[k] != kb[k]:
            changed.append({"key": list(k), "a": ka[k], "b": kb[k]})

    return {
        "columns_a": cols_a,
        "columns_b": cols_b,
        "key_columns": key_cols,
        "only_a": only_a[:2000],
        "only_b": only_b[:2000],
        "changed": changed[:2000],
        "counts": {"only_a": len(only_a), "only_b": len(only_b),
                   "changed": len(changed),
                   "same": len(ka.keys() & kb.keys()) - len(changed)},
    }
