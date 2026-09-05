"""
Background job engine.

A fixed pool of worker threads pulls queued jobs out of SQLite, streams the
execution from the appropriate runner container, persists the normalised
result, and runs the triage rules.  Every interesting moment is published on
the broker so the browser can follow along live.
"""

from __future__ import annotations

import hashlib
import json
import queue
import threading
import time
import traceback
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from . import catalog, config, parsers, runner_client, triage
from .db import audit, session_scope
from .events import broker
from .models import Evidence, Finding, Job, utcnow

# ---------------------------------------------------------------------------
# state
# ---------------------------------------------------------------------------
_queue: "queue.Queue[int]" = queue.Queue()
_cancel_requested: set[str] = set()
_cancel_lock = threading.Lock()
_threads: List[threading.Thread] = []
_stop = threading.Event()
aux_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="mf-aux")

_result_cache: "OrderedDict[str, dict]" = OrderedDict()
_result_cache_lock = threading.Lock()
RESULT_CACHE_MAX = 12


# ---------------------------------------------------------------------------
# result persistence
# ---------------------------------------------------------------------------
def result_path(uid: str):
    return config.RESULT_DIR / f"{uid}.json"


def log_path(uid: str):
    return config.LOG_DIR / f"{uid}.log"


def save_result(uid: str, payload: dict) -> str:
    path = result_path(uid)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, default=str)
    tmp.replace(path)
    with _result_cache_lock:
        _result_cache[uid] = payload
        while len(_result_cache) > RESULT_CACHE_MAX:
            _result_cache.popitem(last=False)
    return str(path)


def load_result(uid: str) -> Optional[dict]:
    with _result_cache_lock:
        hit = _result_cache.get(uid)
        if hit is not None:
            _result_cache.move_to_end(uid)
            return hit
    path = result_path(uid)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return None
    with _result_cache_lock:
        _result_cache[uid] = data
        while len(_result_cache) > RESULT_CACHE_MAX:
            _result_cache.popitem(last=False)
    return data


def read_log(uid: str, tail: int = 0) -> str:
    path = log_path(uid)
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""
    if tail:
        return "\n".join(text.splitlines()[-tail:])
    return text


# ---------------------------------------------------------------------------
# queue API
# ---------------------------------------------------------------------------
def submit(job_id: int) -> None:
    _queue.put(job_id)


def request_cancel(job: Job) -> None:
    with _cancel_lock:
        _cancel_requested.add(job.uid)
    if job.status == "running":
        runner_client.cancel(job.engine, job.uid)


def _cancelled(uid: str) -> bool:
    with _cancel_lock:
        return uid in _cancel_requested


def _clear_cancel(uid: str) -> None:
    with _cancel_lock:
        _cancel_requested.discard(uid)


def queue_depth() -> int:
    return _queue.qsize()


# ---------------------------------------------------------------------------
# job creation
# ---------------------------------------------------------------------------
def create_jobs(evidence: Evidence, engine: str, plugins: List[str],
                args: Optional[Dict[str, Any]] = None, profile: str = "",
                batch_id: Optional[int] = None) -> List[Job]:
    """Persist Job rows and push them onto the queue. Returns the new jobs."""
    created: List[Job] = []
    with session_scope() as s:
        for plugin in plugins:
            meta = catalog.meta_of(engine, plugin)
            job = Job(
                uid=str(uuid.uuid4()),
                evidence_id=evidence.id,
                batch_id=batch_id,
                engine=engine,
                plugin=plugin,
                plugin_label=meta.get("label", plugin),
                family=meta.get("family", "other"),
                args=(args or {}).get(plugin, {}) if isinstance(
                    (args or {}).get(plugin, None), dict) else (args or {}),
                profile=profile or "",
                status="queued",
            )
            s.add(job)
            created.append(job)
        s.flush()
        ids = [j.id for j in created]
    for jid in ids:
        submit(jid)
    broker.publish("jobs", {"type": "queued", "ids": ids}, keep=False)
    audit("jobs.create", str(evidence.id),
          f"{engine}: {len(plugins)} plugin(s) queued")
    return created


# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------
def _publish_job(job: Job, extra: Optional[dict] = None) -> None:
    payload = {
        "type": "job",
        "id": job.id,
        "uid": job.uid,
        "evidence_id": job.evidence_id,
        "engine": job.engine,
        "plugin": job.plugin,
        "label": job.plugin_label,
        "status": job.status,
        "progress": round(job.progress or 0, 1),
        "rows": job.row_count,
        "duration": round(job.duration or 0, 1),
        "error": job.error[:400] if job.error else "",
    }
    if extra:
        payload.update(extra)
    broker.publish(f"job:{job.uid}", payload)
    broker.publish("jobs", payload, keep=False)


def _build_context(evidence_id: int, family: str) -> Dict[str, List[dict]]:
    """Load prior results this family's rules want to cross-check against."""
    needs = {"process_scan": ["processes"], "psxview": ["processes"]}.get(family, [])
    if not needs:
        return {}
    ctx: Dict[str, List[dict]] = {}
    with session_scope() as s:
        for want in needs:
            job = s.scalars(
                select(Job)
                .where(Job.evidence_id == evidence_id, Job.family == want,
                       Job.status == "success")
                .order_by(Job.finished_at.desc())
            ).first()
            if not job:
                continue
            data = load_result(job.uid)
            if data:
                ctx[want] = parsers.to_dicts(data, limit=triage.MAX_ROWS)
    return ctx


def run_job(job_id: int) -> None:
    with session_scope() as s:
        job = s.get(Job, job_id)
        if job is None:
            return
        if job.status not in ("queued",):
            return
        evidence = s.get(Evidence, job.evidence_id)
        if evidence is None:
            job.status = "failed"
            job.error = "evidence record disappeared"
            return
        if _cancelled(job.uid):
            job.status = "cancelled"
            job.finished_at = utcnow()
            _clear_cancel(job.uid)
            _publish_job(job)
            return
        job.status = "running"
        job.started_at = utcnow()
        job.progress = 0.0
        snapshot = {
            "uid": job.uid, "engine": job.engine, "plugin": job.plugin,
            "profile": job.profile, "args": dict(job.args or {}),
            "image": evidence.path, "evidence_id": evidence.id,
            "family": job.family,
        }
        _publish_job(job)

    uid = snapshot["uid"]
    logfile = log_path(uid)
    started = time.time()
    result_payload = None
    result_fmt = ""
    artifacts: List[dict] = []
    rc: Optional[int] = None
    error = ""
    command = ""
    timed_out = False

    from .db import get_setting
    try:
        job_timeout = int(get_setting("job_timeout", str(config.JOB_TIMEOUT)))
    except (TypeError, ValueError):
        job_timeout = config.JOB_TIMEOUT

    payload = {
        "job_id": uid,
        "image": snapshot["image"],
        "plugin": snapshot["plugin"],
        "args": snapshot["args"],
        "timeout": job_timeout,
    }
    if snapshot["engine"] == "vol2" and snapshot["profile"]:
        payload["profile"] = snapshot["profile"]

    try:
        with open(logfile, "a", encoding="utf-8") as log:
            def emit(line: str, kind: str = "log") -> None:
                stamp = time.strftime("%H:%M:%S")
                log.write(f"[{stamp}] {line}\n")
                log.flush()
                broker.publish(f"job:{uid}",
                               {"type": kind, "line": line, "ts": stamp})

            emit(f"Engine: {snapshot['engine']}  Plugin: {snapshot['plugin']}")
            if snapshot["profile"]:
                emit(f"Profile: {snapshot['profile']}")
            if snapshot["args"]:
                emit(f"Arguments: {json.dumps(snapshot['args'])}")

            for event in runner_client.stream_run(snapshot["engine"], payload,
                                                  timeout=job_timeout + 120):
                kind = event.get("t")
                if _cancelled(uid):
                    emit("Cancellation requested — terminating the plugin.")
                    runner_client.cancel(snapshot["engine"], uid)
                    raise _Cancelled()

                if kind == "log":
                    emit(event.get("line", ""))
                elif kind == "status":
                    if event.get("command"):
                        command = event["command"]
                        emit(f"$ {command}")
                    emit(f"state: {event.get('state')}", kind="status")
                elif kind == "progress":
                    pct = float(event.get("pct") or 0)
                    broker.publish(f"job:{uid}", {"type": "progress", "pct": pct})
                    with session_scope() as s:
                        j = s.get(Job, job_id)
                        if j:
                            j.progress = pct
                elif kind == "heartbeat":
                    broker.publish(f"job:{uid}",
                                   {"type": "heartbeat",
                                    "elapsed": event.get("elapsed")}, keep=False)
                elif kind == "result":
                    result_payload = event.get("data")
                    result_fmt = event.get("format", "text")
                    artifacts = event.get("artifacts") or []
                elif kind == "done":
                    rc = event.get("rc")
                    timed_out = bool(event.get("timed_out"))
                    if event.get("error"):
                        error = str(event["error"])
                        emit("ERROR: " + error)
                    if event.get("stderr_tail"):
                        emit("--- stderr tail ---")
                        for ln in str(event["stderr_tail"]).splitlines():
                            emit(ln)
    except _Cancelled:
        _finish(job_id, "cancelled", rc=-9, duration=time.time() - started,
                error="cancelled by user", command=command)
        _clear_cancel(uid)
        return
    except Exception as exc:
        tb = traceback.format_exc(limit=4)
        try:
            with open(logfile, "a", encoding="utf-8") as log:
                log.write(f"\n[runner-client error] {exc}\n{tb}\n")
        except Exception:
            pass
        broker.publish(f"job:{uid}", {"type": "log", "line": f"ERROR: {exc}"})
        _finish(job_id, "failed", rc=1, duration=time.time() - started,
                error=f"{type(exc).__name__}: {exc}", command=command)
        return

    # ---- normalise + persist ------------------------------------------------
    norm = {"format": "text", "columns": [], "rows": [], "row_count": 0, "text": ""}
    try:
        if result_payload is not None:
            norm = parsers.normalize(snapshot["engine"], result_fmt, result_payload)
    except Exception as exc:
        error = error or f"failed to parse plugin output: {exc}"

    norm["artifacts"] = artifacts
    norm["engine"] = snapshot["engine"]
    norm["plugin"] = snapshot["plugin"]
    save_result(uid, norm)

    status = "success"
    if timed_out:
        status = "failed"
        error = error or "plugin exceeded the configured timeout"
    elif rc not in (0, None):
        # A non-zero exit with usable rows still counts as a result.
        if norm.get("row_count"):
            status = "success"
        else:
            status = "failed"
            error = error or f"plugin exited with code {rc}"
    elif norm.get("row_count", 0) == 0 and not (norm.get("text") or "").strip():
        status = "empty"

    _finish(job_id, status, rc=rc, duration=time.time() - started, error=error,
            columns=norm.get("columns", []), row_count=norm.get("row_count", 0),
            result_format=norm.get("format", ""), result_path=str(result_path(uid)),
            artifacts=artifacts, command=command)

    # ---- triage -------------------------------------------------------------
    if status == "success":
        try:
            _run_triage(job_id, snapshot, norm)
        except Exception as exc:
            broker.publish(f"job:{uid}",
                           {"type": "log", "line": f"triage failed: {exc}"})


class _Cancelled(Exception):
    pass


def _finish(job_id: int, status: str, **fields) -> None:
    with session_scope() as s:
        job = s.get(Job, job_id)
        if job is None:
            return
        job.status = status
        job.finished_at = utcnow()
        job.progress = 100.0 if status == "success" else job.progress
        for key, value in fields.items():
            if value is None:
                continue
            setattr(job, key, value)
        s.flush()
        _publish_job(job, {"final": True})


def _run_triage(job_id: int, snapshot: dict, norm: dict) -> None:
    from .db import get_setting
    if get_setting("auto_triage", "1") != "1":
        return
    family = snapshot["family"]
    if family not in triage.RULES:
        return
    ctx = _build_context(snapshot["evidence_id"], family)
    findings = triage.analyze(family, norm, ctx)
    if not findings:
        return
    with session_scope() as s:
        # replace previous findings for this job (re-runs shouldn't duplicate)
        for old in s.scalars(select(Finding).where(Finding.job_id == job_id)):
            s.delete(old)
        for f in findings:
            s.add(Finding(
                job_id=job_id,
                evidence_id=snapshot["evidence_id"],
                rule_id=f["rule_id"],
                severity=f["severity"],
                category=f["category"],
                title=f["title"],
                detail=f["detail"][:8000],
                recommendation=f.get("recommendation", "")[:2000],
                score=f["score"],
                context=f.get("context") or {},
            ))
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    broker.publish(f"job:{snapshot['uid']}",
                   {"type": "findings", "counts": counts, "total": len(findings)})
    broker.publish("jobs", {"type": "findings", "evidence_id": snapshot["evidence_id"],
                            "counts": counts}, keep=False)


# ---------------------------------------------------------------------------
# auxiliary tasks: hashing + image identification
# ---------------------------------------------------------------------------
def hash_evidence(evidence_id: int) -> None:
    with session_scope() as s:
        ev = s.get(Evidence, evidence_id)
        if ev is None:
            return
        path = ev.path
        ev.hash_state = "running"
    local = _container_path(path)
    md5 = hashlib.md5()
    sha = hashlib.sha256()
    try:
        with open(local, "rb") as fh:
            while True:
                chunk = fh.read(8 * 1024 * 1024)
                if not chunk:
                    break
                md5.update(chunk)
                sha.update(chunk)
        state, m, sh = "done", md5.hexdigest(), sha.hexdigest()
    except Exception:
        state, m, sh = "error", "", ""
    with session_scope() as s:
        ev = s.get(Evidence, evidence_id)
        if ev:
            ev.md5, ev.sha256, ev.hash_state = m, sh, state
    broker.publish("evidence", {"type": "hash", "evidence_id": evidence_id,
                                "state": state, "sha256": sh}, keep=False)


def identify_evidence(evidence_id: int, engine_hint: str = "") -> None:
    with session_scope() as s:
        ev = s.get(Evidence, evidence_id)
        if ev is None:
            return
        ev.identify_state = "running"
        path = ev.path
    broker.publish("evidence", {"type": "identify", "evidence_id": evidence_id,
                                "state": "running"}, keep=False)

    detail: Dict[str, Any] = {}
    detected_os = ""
    profiles: List[str] = []

    v3 = runner_client.identify("vol3", path)
    detail["vol3"] = v3
    if v3.get("os"):
        detected_os = v3["os"]

    if detected_os in ("", "windows"):
        v2 = runner_client.identify("vol2", path)
        detail["vol2"] = {k: v for k, v in v2.items() if k != "raw"}
        profiles = v2.get("profiles") or []
        if profiles and not detected_os:
            detected_os = "windows"

    with session_scope() as s:
        ev = s.get(Evidence, evidence_id)
        if ev:
            ev.detected_os = detected_os or ""
            ev.vol2_profile_candidates = profiles
            if profiles and not ev.vol2_profile:
                ev.vol2_profile = profiles[0]
            ev.identify_detail = detail
            ev.identify_state = "done" if (detected_os or profiles) else "unknown"
    broker.publish("evidence", {"type": "identify", "evidence_id": evidence_id,
                                "state": "done", "os": detected_os,
                                "profiles": profiles}, keep=False)
    audit("evidence.identify", str(evidence_id),
          f"os={detected_os} profiles={','.join(profiles[:3])}")


def _container_path(path: str) -> str:
    """Evidence paths are recorded as the runner sees them (/evidence/...);
    inside the web container the same bind mount is at MF_EVIDENCE_DIR."""
    import os
    if os.path.exists(path):
        return path
    name = os.path.basename(path)
    candidate = config.EVIDENCE_DIR / name
    return str(candidate)


# ---------------------------------------------------------------------------
# pool lifecycle
# ---------------------------------------------------------------------------
def _worker_loop(idx: int) -> None:
    while not _stop.is_set():
        try:
            job_id = _queue.get(timeout=1.0)
        except queue.Empty:
            continue
        try:
            run_job(job_id)
        except Exception:
            traceback.print_exc()
        finally:
            _queue.task_done()


def start(workers: Optional[int] = None) -> None:
    n = workers or config.WORKERS
    _requeue_orphans()
    for i in range(max(1, n)):
        t = threading.Thread(target=_worker_loop, args=(i,), daemon=True,
                             name=f"mf-worker-{i}")
        t.start()
        _threads.append(t)


def stop() -> None:
    _stop.set()


def _requeue_orphans() -> None:
    """Jobs left 'running' by a crash/restart go back on the queue."""
    with session_scope() as s:
        rows = list(s.scalars(select(Job).where(Job.status.in_(["running", "queued"]))
                              .order_by(Job.id)))
        ids = []
        for job in rows:
            job.status = "queued"
            job.progress = 0.0
            ids.append(job.id)
    for jid in ids:
        submit(jid)
