"""HTML pages."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import catalog, config, db, reporting, runner_client, services, triage, worker
from ..models import Batch, Case, Evidence, Finding, Job, Report
from ..templating import templates

router = APIRouter(default_response_class=HTMLResponse)


def _ctx(request: Request, **kw):
    base = {"request": request, "nav": kw.pop("nav", ""), "settings": db.all_settings()}
    base.update(kw)
    return base


# ---------------------------------------------------------------------------
@router.get("/")
def dashboard(request: Request, s: Session = Depends(db.get_session)):
    stats = services.dashboard(s)
    engines = runner_client.engine_status()
    return templates.TemplateResponse(request, "dashboard.html", _ctx(
        request, nav="dashboard", stats=stats, engines=engines,
        queue_depth=worker.queue_depth()))


# ---------------------------------------------------------------------------
@router.get("/evidence")
def evidence_list(request: Request, q: str = "", case_id: Optional[int] = None,
                  s: Session = Depends(db.get_session)):
    stmt = select(Evidence).order_by(Evidence.created_at.desc())
    if case_id:
        stmt = stmt.where(Evidence.case_id == case_id)
    items = list(s.scalars(stmt))
    if q:
        needle = q.lower()
        items = [e for e in items
                 if needle in e.name.lower() or needle in e.filename.lower()
                 or needle in (e.sha256 or "").lower()]
    rollups = {e.id: services.evidence_rollup(s, e.id) for e in items}
    cases = list(s.scalars(select(Case).order_by(Case.created_at.desc())))
    return templates.TemplateResponse(request, "evidence_list.html", _ctx(
        request, nav="evidence", items=items, rollups=rollups, q=q,
        cases=cases, case_id=case_id,
        max_upload=config.MAX_UPLOAD_BYTES))


@router.get("/evidence/{evidence_id}")
def evidence_detail(evidence_id: int, request: Request,
                    tab: str = "overview",
                    s: Session = Depends(db.get_session)):
    ev = s.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(404)
    jobs = list(s.scalars(
        select(Job).where(Job.evidence_id == evidence_id)
        .order_by(Job.created_at.desc())))
    findings = list(s.scalars(
        select(Finding).where(Finding.evidence_id == evidence_id)))
    findings.sort(key=lambda f: (f.rank, -f.id))
    batches = list(s.scalars(
        select(Batch).where(Batch.evidence_id == evidence_id)
        .order_by(Batch.created_at.desc())))
    reports = list(s.scalars(
        select(Report).where(Report.evidence_id == evidence_id)
        .order_by(Report.created_at.desc())))
    rollup = services.evidence_rollup(s, evidence_id)
    cases = list(s.scalars(select(Case).order_by(Case.name)))

    by_family: dict = {}
    for j in jobs:
        if j.status == "success":
            by_family.setdefault(j.family or "other", []).append(j)

    return templates.TemplateResponse(request, "evidence_detail.html", _ctx(
        request, nav="evidence", ev=ev, jobs=jobs, findings=findings,
        batches=batches, reports=reports, rollup=rollup, tab=tab,
        cases=cases, by_family=by_family))


@router.get("/evidence/{evidence_id}/analyze")
def analyze_page(evidence_id: int, request: Request,
                 engine: str = "", preset: str = "",
                 s: Session = Depends(db.get_session)):
    ev = s.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(404)
    engine = engine or db.get_setting("default_engine", "vol3")
    if engine not in config.ENGINES:
        engine = "vol3"

    available = services.available_plugins(engine)
    os_name = services.os_for(ev)
    if engine == "vol3" and not services.is_windows_crash_dump(ev):
        crashinfo = available.get("windows.crashinfo.Crashinfo")
        if crashinfo:
            crashinfo["available"] = False
            crashinfo["unavailable_reason"] = "needs a Windows crash dump (.dmp), not a raw image"
    groups = catalog.grouped(available, os_name)
    all_groups = catalog.grouped(available, "")
    engines = runner_client.engine_status()
    profiles = runner_client.vol2_profiles() if engine == "vol2" else []

    preset_preview = {}
    for key in catalog.PRESETS:
        preset_preview[key] = catalog.preset_plugins(key, engine, os_name, available)

    return templates.TemplateResponse(request, "analyze.html", _ctx(
        request, nav="evidence", ev=ev, engine=engine, engines=engines,
        groups=groups, all_groups=all_groups, os_name=os_name,
        presets=catalog.PRESETS, preset_preview=preset_preview,
        profiles=profiles, selected_preset=preset,
        popular=catalog.popular(engine, os_name),
        plugin_count=len([m for m in available.values()
                          if m.get("available", True)])))


# ---------------------------------------------------------------------------
@router.get("/jobs")
def jobs_page(request: Request, status: str = "", engine: str = "",
              evidence_id: Optional[int] = None, q: str = "",
              page: int = 1, s: Session = Depends(db.get_session)):
    stmt = select(Job).order_by(Job.created_at.desc())
    if status:
        stmt = stmt.where(Job.status == status)
    if engine:
        stmt = stmt.where(Job.engine == engine)
    if evidence_id:
        stmt = stmt.where(Job.evidence_id == evidence_id)
    rows = list(s.scalars(stmt))
    if q:
        needle = q.lower()
        rows = [j for j in rows if needle in j.plugin.lower()
                or needle in (j.plugin_label or "").lower()]
    pager = services.paginate(rows, page, 50)
    return templates.TemplateResponse(request, "jobs.html", _ctx(
        request, nav="history", pager=pager, status=status, engine=engine,
        evidence_id=evidence_id, q=q,
        evidence_map=services.evidence_map(s),
        queue_depth=worker.queue_depth()))


@router.get("/jobs/{job_id}")
def job_detail(job_id: int, request: Request, page: int = 1,
               q: str = "", sort: str = "", dir: str = "asc",
               per_page: int = 100, s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    ev = s.get(Evidence, job.evidence_id)
    data = worker.load_result(job.uid) or {}
    columns = data.get("columns") or []
    rows = services.filter_sort_rows(columns, data.get("rows") or [], q, sort, dir)
    pager = services.paginate(rows, page, max(10, min(per_page, 1000)))
    findings = list(s.scalars(select(Finding).where(Finding.job_id == job_id)))
    findings.sort(key=lambda f: f.rank)
    log = worker.read_log(job.uid, tail=800)
    meta = catalog.meta_of(job.engine, job.plugin)
    siblings = list(s.scalars(
        select(Job).where(Job.evidence_id == job.evidence_id,
                          Job.plugin == job.plugin, Job.id != job.id)
        .order_by(Job.created_at.desc()).limit(10)))
    return templates.TemplateResponse(request, "job_detail.html", _ctx(
        request, nav="history", job=job, ev=ev, data=data, columns=columns,
        pager=pager, q=q, sort=sort, dir=dir, per_page=per_page,
        findings=findings, log=log, meta=meta, siblings=siblings,
        text=(data.get("text") or "")))


# ---------------------------------------------------------------------------
@router.get("/findings")
def findings_page(request: Request, severity: str = "", state: str = "open",
                  evidence_id: Optional[int] = None, category: str = "",
                  page: int = 1, s: Session = Depends(db.get_session)):
    stmt = select(Finding).order_by(Finding.id.desc())
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if state:
        stmt = stmt.where(Finding.state == state)
    if evidence_id:
        stmt = stmt.where(Finding.evidence_id == evidence_id)
    if category:
        stmt = stmt.where(Finding.category == category)
    rows = list(s.scalars(stmt))
    rows.sort(key=lambda f: (f.rank, -f.id))
    pager = services.paginate(rows, page, 60)
    categories = sorted({r[0] for r in s.execute(select(Finding.category)).all() if r[0]})
    jobs = {j.id: j for j in s.scalars(select(Job))}
    return templates.TemplateResponse(request, "findings.html", _ctx(
        request, nav="findings", pager=pager, severity=severity, state=state,
        evidence_id=evidence_id, category=category, categories=categories,
        evidence_map=services.evidence_map(s), jobs=jobs))


# ---------------------------------------------------------------------------
@router.get("/compare")
def compare_page(request: Request, a: Optional[int] = None, b: Optional[int] = None,
                 evidence_id: Optional[int] = None,
                 s: Session = Depends(db.get_session)):
    stmt = select(Job).where(Job.status == "success").order_by(Job.created_at.desc())
    if evidence_id:
        stmt = stmt.where(Job.evidence_id == evidence_id)
    candidates = list(s.scalars(stmt.limit(400)))
    job_a = s.get(Job, a) if a else None
    job_b = s.get(Job, b) if b else None
    diff = None
    if job_a and job_b:
        diff = reporting.compare(job_a, job_b)
    return templates.TemplateResponse(request, "compare.html", _ctx(
        request, nav="compare", candidates=candidates, job_a=job_a, job_b=job_b,
        diff=diff, evidence_map=services.evidence_map(s),
        evidence_id=evidence_id))


# ---------------------------------------------------------------------------
@router.get("/reports")
def reports_page(request: Request, s: Session = Depends(db.get_session)):
    reports = list(s.scalars(select(Report).order_by(Report.created_at.desc())))
    evidence = list(s.scalars(select(Evidence).order_by(Evidence.name)))
    return templates.TemplateResponse(request, "reports.html", _ctx(
        request, nav="reports", reports=reports, evidence=evidence,
        evidence_map=services.evidence_map(s)))


@router.get("/reports/preview/{evidence_id}")
def report_preview(evidence_id: int, request: Request,
                   s: Session = Depends(db.get_session)):
    ctx = reporting.build_context(s, evidence_id)
    ctx["request"] = request
    ctx["standalone"] = False
    return templates.TemplateResponse(request, "report.html", ctx)


# ---------------------------------------------------------------------------
@router.get("/plugins")
def plugins_page(request: Request, engine: str = "vol3", os_name: str = "",
                 q: str = "", s: Session = Depends(db.get_session)):
    if engine not in config.ENGINES:
        engine = "vol3"
    available = services.available_plugins(engine)
    if q:
        needle = q.lower()
        available = {k: v for k, v in available.items()
                     if needle in k.lower() or needle in v["label"].lower()
                     or needle in v["description"].lower()}
    groups = catalog.grouped(available, os_name)
    return templates.TemplateResponse(request, "plugins.html", _ctx(
        request, nav="plugins", engine=engine, groups=groups, q=q,
        os_name=os_name, engines=runner_client.engine_status(),
        total=len(available)))


# ---------------------------------------------------------------------------
@router.get("/cases")
def cases_page(request: Request, s: Session = Depends(db.get_session)):
    cases = list(s.scalars(select(Case).order_by(Case.created_at.desc())))
    rollups = {}
    for c in cases:
        evs = list(s.scalars(select(Evidence).where(Evidence.case_id == c.id)))
        agg = {"evidence": len(evs), "jobs": 0, "findings": 0, "score": 0}
        for e in evs:
            r = services.evidence_rollup(s, e.id)
            agg["jobs"] += r["jobs"]
            agg["findings"] += r["findings"]
            agg["score"] = max(agg["score"], r["risk_score"])
        agg["band"] = triage.risk_band(agg["score"])
        rollups[c.id] = agg
    unassigned = list(s.scalars(
        select(Evidence).where(Evidence.case_id.is_(None))))
    return templates.TemplateResponse(request, "cases.html", _ctx(
        request, nav="cases", cases=cases, rollups=rollups,
        unassigned=unassigned))


# ---------------------------------------------------------------------------
@router.get("/settings")
def settings_page(request: Request, s: Session = Depends(db.get_session)):
    engines = runner_client.engine_status()
    counts = {
        "vol3": len(services.available_plugins("vol3")),
        "vol2": len(services.available_plugins("vol2")),
    }
    profiles = runner_client.vol2_profiles()
    from ..models import Audit
    audit_rows = list(s.scalars(select(Audit).order_by(Audit.id.desc()).limit(80)))
    return templates.TemplateResponse(request, "settings.html", _ctx(
        request, nav="settings", engines=engines, counts=counts,
        profiles=profiles, audit=audit_rows,
        paths={"evidence": str(config.EVIDENCE_DIR), "data": str(config.DATA_DIR),
               "reports": str(config.REPORT_DIR)},
        workers=config.WORKERS, queue_depth=worker.queue_depth()))
