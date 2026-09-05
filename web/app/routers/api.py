"""JSON API, uploads, downloads, live streams and form actions."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
from typing import Any, Dict, List, Optional

from fastapi import (APIRouter, Body, Depends, File, Form, HTTPException,
                     Query, Request, UploadFile)
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               PlainTextResponse, RedirectResponse,
                               StreamingResponse)
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import (catalog, config, db, parsers, reporting, runner_client,
                services, triage, worker)
from ..events import broker, sse
from ..models import Batch, Case, Evidence, Finding, Job, Report, utcnow
from ..templating import templates

router = APIRouter(prefix="/api")


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept and "application/json" not in accept


# ===========================================================================
# health / engines / plugins
# ===========================================================================
@router.get("/health")
def health():
    return {
        "ok": True,
        "app": config.APP_NAME,
        "version": config.VERSION,
        "workers": config.WORKERS,
        "queue_depth": worker.queue_depth(),
        "engines": {e["key"]: e["online"] for e in runner_client.engine_status()},
    }


@router.get("/engines")
def engines(refresh: bool = False):
    if refresh:
        runner_client.invalidate()
    return {"engines": runner_client.engine_status()}


@router.get("/plugins/{engine}")
def plugins(engine: str, os_name: str = "", refresh: bool = False,
            popular_only: bool = False):
    if engine not in config.ENGINES:
        raise HTTPException(404, "unknown engine")
    available = services.available_plugins(engine, force=refresh)
    items = list(available.values())
    if os_name:
        items = [m for m in items if m["os"] in (os_name, "generic")]
    if popular_only:
        items = [m for m in items if m["popular"]]
    return {"engine": engine, "count": len(items),
            "plugins": sorted(items, key=lambda m: (m["category"], m["label"]))}


@router.get("/presets/{engine}")
def presets(engine: str, os_name: str = "windows"):
    available = services.available_plugins(engine)
    out = []
    for key, preset in catalog.PRESETS.items():
        plugins_ = catalog.preset_plugins(key, engine, os_name, available)
        out.append({**{k: v for k, v in preset.items() if k != "plugins"},
                    "resolved": plugins_, "count": len(plugins_)})
    return {"presets": out}


@router.get("/profiles")
def profiles(refresh: bool = False):
    return {"profiles": runner_client.vol2_profiles(force=refresh)}


# ===========================================================================
# evidence
# ===========================================================================
@router.put("/evidence/raw")
async def upload_raw(request: Request, filename: str = Query(...),
                     name: str = Query(""), case_id: Optional[int] = Query(None)):
    """Streaming upload — the browser PUTs the file body directly."""
    safe = services.safe_filename(filename)
    dest = services.unique_evidence_path(safe)
    written = 0
    try:
        with open(dest, "wb") as fh:
            async for chunk in request.stream():
                if not chunk:
                    continue
                written += len(chunk)
                if written > config.MAX_UPLOAD_BYTES:
                    fh.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(
                        413, f"upload exceeds the {config.MAX_UPLOAD_BYTES} byte limit")
                fh.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        dest.unlink(missing_ok=True)
        raise HTTPException(500, f"upload failed: {exc}")

    if written == 0:
        dest.unlink(missing_ok=True)
        raise HTTPException(400, "empty upload")

    with db.session_scope() as s:
        ev = Evidence(
            name=(name or dest.stem)[:200],
            filename=dest.name,
            path=services.runner_path(dest),
            size=written,
            case_id=case_id,
            source="upload",
        )
        s.add(ev)
        s.flush()
        evidence_id = ev.id
    db.audit("evidence.upload", str(evidence_id), f"{dest.name} ({written} bytes)")
    worker.aux_pool.submit(worker.hash_evidence, evidence_id)
    if db.get_setting("auto_identify", "1") == "1":
        worker.aux_pool.submit(worker.identify_evidence, evidence_id)
    return {"ok": True, "evidence_id": evidence_id, "size": written,
            "redirect": f"/evidence/{evidence_id}"}


@router.post("/evidence/upload")
async def upload_form(request: Request, file: UploadFile = File(...),
                      name: str = Form(""), case_id: Optional[int] = Form(None)):
    """Classic multipart upload (fallback for non-JS clients)."""
    safe = services.safe_filename(file.filename or "image.raw")
    dest = services.unique_evidence_path(safe)
    with open(dest, "wb") as fh:
        shutil.copyfileobj(file.file, fh, length=8 * 1024 * 1024)
    size = dest.stat().st_size
    with db.session_scope() as s:
        ev = Evidence(name=(name or dest.stem)[:200], filename=dest.name,
                      path=services.runner_path(dest), size=size,
                      case_id=case_id or None, source="upload")
        s.add(ev)
        s.flush()
        evidence_id = ev.id
    worker.aux_pool.submit(worker.hash_evidence, evidence_id)
    if db.get_setting("auto_identify", "1") == "1":
        worker.aux_pool.submit(worker.identify_evidence, evidence_id)
    return RedirectResponse(f"/evidence/{evidence_id}", status_code=303)


@router.post("/evidence/scan")
def scan_dir(request: Request):
    with db.session_scope() as s:
        added = services.scan_evidence_dir(s)
        ids = [e.id for e in added]
        names = [e.filename for e in added]
    for eid in ids:
        worker.aux_pool.submit(worker.hash_evidence, eid)
        if db.get_setting("auto_identify", "1") == "1":
            worker.aux_pool.submit(worker.identify_evidence, eid)
    db.audit("evidence.scan", "", f"registered {len(ids)}: {', '.join(names)}")
    if _wants_html(request):
        return RedirectResponse("/evidence", status_code=303)
    return {"ok": True, "added": ids, "names": names}


@router.post("/evidence/{evidence_id}/identify")
def identify(evidence_id: int, request: Request):
    worker.aux_pool.submit(worker.identify_evidence, evidence_id)
    if _wants_html(request):
        return RedirectResponse(f"/evidence/{evidence_id}", status_code=303)
    return {"ok": True, "queued": True}


@router.post("/evidence/{evidence_id}/hash")
def rehash(evidence_id: int, request: Request):
    worker.aux_pool.submit(worker.hash_evidence, evidence_id)
    if _wants_html(request):
        return RedirectResponse(f"/evidence/{evidence_id}", status_code=303)
    return {"ok": True, "queued": True}


@router.post("/evidence/{evidence_id}/update")
def update_evidence(evidence_id: int, request: Request,
                    name: str = Form(""), notes: str = Form(""),
                    case_id: str = Form(""), vol2_profile: str = Form(""),
                    detected_os: str = Form(""),
                    s: Session = Depends(db.get_session)):
    ev = s.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(404)
    if name:
        ev.name = name[:200]
    ev.notes = notes
    ev.case_id = int(case_id) if case_id.strip().isdigit() else None
    if vol2_profile:
        ev.vol2_profile = vol2_profile
    if detected_os:
        ev.detected_os = detected_os
    s.commit()
    db.audit("evidence.update", str(evidence_id), name)
    if _wants_html(request):
        return RedirectResponse(f"/evidence/{evidence_id}", status_code=303)
    return {"ok": True}


@router.post("/evidence/{evidence_id}/delete")
def delete_evidence(evidence_id: int, request: Request,
                    delete_file: str = Form(""),
                    s: Session = Depends(db.get_session)):
    ev = s.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(404)
    filename = ev.filename
    s.delete(ev)
    s.commit()
    if delete_file:
        try:
            (config.EVIDENCE_DIR / filename).unlink(missing_ok=True)
        except Exception:
            pass
    db.audit("evidence.delete", str(evidence_id), filename)
    if _wants_html(request):
        return RedirectResponse("/evidence", status_code=303)
    return {"ok": True}


@router.get("/evidence/{evidence_id}")
def evidence_json(evidence_id: int, rows: bool = False,
                  s: Session = Depends(db.get_session)):
    try:
        return reporting.evidence_json(s, evidence_id, include_rows=rows)
    except ValueError:
        raise HTTPException(404)


# ===========================================================================
# analysis launch
# ===========================================================================
@router.post("/analyze")
async def analyze(request: Request, s: Session = Depends(db.get_session)):
    """Accepts either a JSON body or an HTML form post."""
    ctype = request.headers.get("content-type", "")
    if ctype.startswith("application/json"):
        body = await request.json()
        plugins_ = body.get("plugins") or []
        preset = body.get("preset") or ""
        engine = body.get("engine") or "vol3"
        profile = body.get("profile") or ""
        args = body.get("args") or {}
        evidence_id = int(body.get("evidence_id"))
    else:
        form = await request.form()
        plugins_ = [v for k, v in form.multi_items() if k == "plugins"]
        preset = str(form.get("preset") or "")
        engine = str(form.get("engine") or "vol3")
        profile = str(form.get("profile") or "")
        evidence_id = int(form.get("evidence_id"))
        args = {}
        for key, value in form.multi_items():
            if key.startswith("arg::") and str(value).strip():
                _, plugin, flag = key.split("::", 2)
                args.setdefault(plugin, {})[flag] = value

    if engine not in config.ENGINES:
        raise HTTPException(400, "unknown engine")
    ev = s.get(Evidence, evidence_id)
    if ev is None:
        raise HTTPException(404, "evidence not found")

    available = services.available_plugins(engine)
    os_name = services.os_for(ev)
    if preset:
        plugins_ = catalog.preset_plugins(preset, engine, os_name, available) or plugins_
    plugins_ = [p for p in dict.fromkeys(plugins_) if p]
    if not plugins_:
        raise HTTPException(400, "no plugins selected")

    if engine == "vol2" and not profile:
        profile = ev.vol2_profile or ""

    batch = Batch(evidence_id=evidence_id,
                  name=(catalog.PRESETS.get(preset, {}).get("label")
                        or f"{len(plugins_)} plugin(s)"),
                  engine=engine, preset=preset)
    s.add(batch)
    s.commit()

    jobs = worker.create_jobs(ev, engine, plugins_, args=args, profile=profile,
                              batch_id=batch.id)

    if _wants_html(request):
        return RedirectResponse(f"/evidence/{evidence_id}?tab=runs", status_code=303)
    return {"ok": True, "batch_id": batch.id,
            "jobs": [{"id": j.id, "uid": j.uid, "plugin": j.plugin} for j in jobs],
            "redirect": f"/evidence/{evidence_id}?tab=runs"}


# ===========================================================================
# jobs
# ===========================================================================
@router.get("/jobs")
def list_jobs(status: str = "", engine: str = "", evidence_id: Optional[int] = None,
              limit: int = 100, s: Session = Depends(db.get_session)):
    stmt = select(Job).order_by(Job.id.desc()).limit(min(limit, 1000))
    if status:
        stmt = stmt.where(Job.status == status)
    if engine:
        stmt = stmt.where(Job.engine == engine)
    if evidence_id:
        stmt = stmt.where(Job.evidence_id == evidence_id)
    jobs = list(s.scalars(stmt))
    return {"jobs": [{
        "id": j.id, "uid": j.uid, "evidence_id": j.evidence_id,
        "engine": j.engine, "plugin": j.plugin, "label": j.plugin_label,
        "status": j.status, "progress": j.progress, "rows": j.row_count,
        "duration": j.duration, "created_at": j.created_at.isoformat(),
        "error": j.error,
    } for j in jobs]}


@router.get("/jobs/{job_id}")
def job_json(job_id: int, rows: bool = False, limit: int = 500,
             s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    data = worker.load_result(job.uid) or {}
    payload = {
        "id": job.id, "uid": job.uid, "engine": job.engine, "plugin": job.plugin,
        "label": job.plugin_label, "status": job.status, "rc": job.rc,
        "progress": job.progress, "duration": job.duration,
        "row_count": job.row_count, "columns": data.get("columns", []),
        "error": job.error, "command": job.command, "args": job.args,
        "profile": job.profile, "artifacts": job.artifacts,
        "evidence_id": job.evidence_id,
    }
    if rows:
        payload["rows"] = (data.get("rows") or [])[:limit]
        payload["text"] = data.get("text", "")
    return payload


@router.get("/jobs/{job_id}/rows")
def job_rows(job_id: int, page: int = 1, per_page: int = 100, q: str = "",
             sort: str = "", dir: str = "asc",
             s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    data = worker.load_result(job.uid) or {}
    cols = data.get("columns") or []
    rows = services.filter_sort_rows(cols, data.get("rows") or [], q, sort, dir)
    pager = services.paginate(rows, page, max(10, min(per_page, 1000)))
    return {"columns": cols, **pager}


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: int, request: Request, s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    if job.is_terminal:
        return {"ok": False, "reason": "already finished"}
    worker.request_cancel(job)
    db.audit("job.cancel", str(job_id), job.plugin)
    if _wants_html(request):
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)
    return {"ok": True}


@router.post("/jobs/{job_id}/rerun")
def rerun_job(job_id: int, request: Request, s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    ev = s.get(Evidence, job.evidence_id)
    if ev is None:
        raise HTTPException(404, "evidence gone")
    new = worker.create_jobs(ev, job.engine, [job.plugin], args=job.args or {},
                             profile=job.profile)
    target = new[0]
    if _wants_html(request):
        return RedirectResponse(f"/jobs/{target.id}", status_code=303)
    return {"ok": True, "job_id": target.id}


@router.post("/jobs/{job_id}/delete")
def delete_job(job_id: int, request: Request, s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    evidence_id = job.evidence_id
    uid = job.uid
    s.delete(job)
    s.commit()
    for path in (worker.result_path(uid), worker.log_path(uid)):
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
    if _wants_html(request):
        return RedirectResponse(f"/evidence/{evidence_id}?tab=runs", status_code=303)
    return {"ok": True}


@router.get("/jobs/{job_id}/log")
def job_log(job_id: int, s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    return PlainTextResponse(worker.read_log(job.uid) or "(no log yet)")


@router.get("/jobs/{job_id}/csv")
def job_csv(job_id: int, s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    body = reporting.job_csv(job)
    fname = f"{job.engine}-{job.plugin.replace('.', '_')}-{job.id}.csv"
    return PlainTextResponse(body, media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="{fname}"'})


@router.get("/jobs/{job_id}/download.json")
def job_download_json(job_id: int, s: Session = Depends(db.get_session)):
    job = s.get(Job, job_id)
    if job is None:
        raise HTTPException(404)
    data = worker.load_result(job.uid) or {}
    fname = f"{job.engine}-{job.plugin.replace('.', '_')}-{job.id}.json"
    return JSONResponse(data, headers={
        "Content-Disposition": f'attachment; filename="{fname}"'})


@router.get("/artifacts/{job_uid}/{name}")
def artifact(job_uid: str, name: str):
    safe = os.path.basename(name)
    path = config.ARTIFACT_DIR / job_uid / safe
    if not path.exists():
        raise HTTPException(404)
    return FileResponse(str(path), filename=safe,
                        media_type="application/octet-stream")


# ===========================================================================
# live streams
# ===========================================================================
@router.get("/stream/job/{job_uid}")
async def stream_job(job_uid: str, request: Request):
    queue_ = broker.subscribe(f"job:{job_uid}")

    async def gen():
        try:
            for old in broker.history(f"job:{job_uid}")[-200:]:
                yield sse("update", old)
            last_ping = time.time()
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue_.get(), timeout=10.0)
                    yield sse("update", payload)
                    if isinstance(payload, dict) and payload.get("final"):
                        yield sse("close", {"ok": True})
                        break
                except asyncio.TimeoutError:
                    if time.time() - last_ping > 10:
                        last_ping = time.time()
                        yield ": ping\n\n"
        finally:
            broker.unsubscribe(f"job:{job_uid}", queue_)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no",
        "Connection": "keep-alive"})


@router.get("/stream/jobs")
async def stream_jobs(request: Request):
    queue_ = broker.subscribe("jobs")

    async def gen():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue_.get(), timeout=10.0)
                    yield sse("update", payload)
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
        finally:
            broker.unsubscribe("jobs", queue_)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ===========================================================================
# findings
# ===========================================================================
@router.post("/findings/{finding_id}/state")
def finding_state(finding_id: int, request: Request, state: str = Form("open"),
                  s: Session = Depends(db.get_session)):
    f = s.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404)
    if state not in ("open", "confirmed", "dismissed"):
        raise HTTPException(400, "bad state")
    f.state = state
    s.commit()
    db.audit("finding.state", str(finding_id), state)
    if _wants_html(request):
        return RedirectResponse(request.headers.get("referer", "/findings"),
                                status_code=303)
    return {"ok": True, "state": state}


@router.post("/evidence/{evidence_id}/retriage")
def retriage(evidence_id: int, request: Request,
             s: Session = Depends(db.get_session)):
    """Re-run every triage rule against already-collected results."""
    jobs = list(s.scalars(
        select(Job).where(Job.evidence_id == evidence_id, Job.status == "success")
        .order_by(Job.id)))
    total = 0
    for job in jobs:
        data = worker.load_result(job.uid)
        if not data:
            continue
        snapshot = {"uid": job.uid, "engine": job.engine, "plugin": job.plugin,
                    "family": job.family, "evidence_id": evidence_id}
        try:
            worker._run_triage(job.id, snapshot, data)
            total += 1
        except Exception:
            continue
    db.audit("evidence.retriage", str(evidence_id), f"{total} runs re-analysed")
    if _wants_html(request):
        return RedirectResponse(f"/evidence/{evidence_id}?tab=findings",
                                status_code=303)
    return {"ok": True, "reanalysed": total}


# ===========================================================================
# reports
# ===========================================================================
@router.post("/reports/generate")
async def generate_report(request: Request, s: Session = Depends(db.get_session)):
    ctype = request.headers.get("content-type", "")
    if ctype.startswith("application/json"):
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)
    evidence_id = int(body.get("evidence_id"))
    fmt = str(body.get("format") or "html").lower()
    include_empty = bool(body.get("include_empty"))
    max_rows = int(body.get("max_rows") or reporting.MAX_REPORT_ROWS)

    ctx = reporting.build_context(s, evidence_id, include_empty=include_empty,
                                  max_rows=max_rows)
    ctx["standalone"] = True
    ctx["request"] = request
    html = templates.get_template("report.html").render(**ctx)

    title = f"{ctx['evidence'].name} analysis report"
    if fmt == "pdf":
        rep = reporting.write_pdf(s, evidence_id, html, title)
    elif fmt == "zip":
        rep = reporting.bundle_zip(s, evidence_id, html)
    elif fmt == "json":
        payload = reporting.evidence_json(s, evidence_id)
        name = f"{reporting._slug(ctx['evidence'].name)}-{reporting._stamp()}.json"
        path = config.REPORT_DIR / name
        path.write_text(json.dumps(payload, indent=2, default=str),
                        encoding="utf-8")
        rep = Report(evidence_id=evidence_id, title=title, fmt="json",
                     path=str(path), size=path.stat().st_size)
        s.add(rep)
        s.flush()
    else:
        rep = reporting.write_html(s, evidence_id, html, title)
    s.commit()
    db.audit("report.generate", str(evidence_id), f"{fmt} -> {rep.path}")

    if _wants_html(request):
        return RedirectResponse(f"/api/reports/{rep.id}/download", status_code=303)
    return {"ok": True, "report_id": rep.id, "format": rep.fmt,
            "download": f"/api/reports/{rep.id}/download"}


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, s: Session = Depends(db.get_session)):
    rep = s.get(Report, report_id)
    if rep is None or not os.path.exists(rep.path):
        raise HTTPException(404)
    media = {"html": "text/html", "pdf": "application/pdf",
             "json": "application/json", "zip": "application/zip",
             "csv": "text/csv"}.get(rep.fmt, "application/octet-stream")
    return FileResponse(rep.path, media_type=media,
                        filename=os.path.basename(rep.path))


@router.post("/reports/{report_id}/delete")
def delete_report(report_id: int, request: Request,
                  s: Session = Depends(db.get_session)):
    rep = s.get(Report, report_id)
    if rep is None:
        raise HTTPException(404)
    try:
        os.unlink(rep.path)
    except Exception:
        pass
    s.delete(rep)
    s.commit()
    if _wants_html(request):
        return RedirectResponse("/reports", status_code=303)
    return {"ok": True}


# ===========================================================================
# cases
# ===========================================================================
@router.post("/cases")
def create_case(request: Request, name: str = Form(...),
                description: str = Form(""), analyst: str = Form(""),
                s: Session = Depends(db.get_session)):
    case = Case(name=name[:200], description=description, analyst=analyst)
    s.add(case)
    s.commit()
    db.audit("case.create", str(case.id), name)
    if _wants_html(request):
        return RedirectResponse("/cases", status_code=303)
    return {"ok": True, "case_id": case.id}


@router.post("/cases/{case_id}/delete")
def delete_case(case_id: int, request: Request,
                s: Session = Depends(db.get_session)):
    case = s.get(Case, case_id)
    if case is None:
        raise HTTPException(404)
    s.delete(case)
    s.commit()
    if _wants_html(request):
        return RedirectResponse("/cases", status_code=303)
    return {"ok": True}


# ===========================================================================
# settings
# ===========================================================================
@router.post("/settings")
async def save_settings(request: Request):
    form = await request.form()
    for key in ("default_engine", "auto_triage", "auto_identify",
                "hide_empty_results", "organisation", "analyst", "job_timeout"):
        if key in form:
            db.set_setting(key, str(form.get(key)))
        elif key in ("auto_triage", "auto_identify", "hide_empty_results"):
            db.set_setting(key, "0")
    runner_client.invalidate()
    db.audit("settings.save", "", "")
    if _wants_html(request):
        return RedirectResponse("/settings", status_code=303)
    return {"ok": True, "settings": db.all_settings()}


@router.post("/cache/clear")
def clear_cache(request: Request):
    runner_client.invalidate()
    if _wants_html(request):
        return RedirectResponse("/settings", status_code=303)
    return {"ok": True}


# ===========================================================================
# HTMX partials
# ===========================================================================
@router.get("/partials/active-jobs", response_class=HTMLResponse)
def partial_active(request: Request, s: Session = Depends(db.get_session)):
    jobs = list(s.scalars(
        select(Job).where(Job.status.in_(["queued", "running"]))
        .order_by(Job.id).limit(40)))
    return templates.TemplateResponse(request, "partials/active_jobs.html", {
        "request": request, "jobs": jobs,
        "evidence_map": services.evidence_map(s),
        "queue_depth": worker.queue_depth()})


@router.get("/partials/job-rows", response_class=HTMLResponse)
def partial_job_rows(request: Request, evidence_id: Optional[int] = None,
                     limit: int = 40, s: Session = Depends(db.get_session)):
    stmt = select(Job).order_by(Job.id.desc()).limit(limit)
    if evidence_id:
        stmt = stmt.where(Job.evidence_id == evidence_id)
    jobs = list(s.scalars(stmt))
    return templates.TemplateResponse(request, "partials/job_rows.html", {
        "request": request, "jobs": jobs,
        "evidence_map": services.evidence_map(s)})
