#!/usr/bin/env python3
"""
Volatility 3 execution shim.

Exposes a tiny HTTP API so the web platform never has to care about which
Python interpreter Volatility needs.  The identical API is implemented by the
Volatility 2 runner (in Python 2.7), so the platform talks to both engines
through one client.

    GET  /health              -> engine metadata
    GET  /plugins             -> discovered plugin catalog
    POST /identify            -> quick OS / kernel identification
    POST /run                 -> NDJSON event stream of a plugin execution
    POST /cancel/{job_id}     -> kill a running execution
"""

import json
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
import uuid

from fastapi import FastAPI, Body
from fastapi.responses import StreamingResponse, JSONResponse

ENGINE = "vol3"
PORT = int(os.environ.get("RUNNER_PORT", "9003"))
SYMBOLS_DIR = os.environ.get("VOL3_SYMBOLS", "/symbols")
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "/artifacts")
DEFAULT_TIMEOUT = int(os.environ.get("RUNNER_TIMEOUT", "7200"))

def _default_vol_cmd():
    """How to invoke the Volatility 3 CLI.

    NOT `python -m volatility3.cli`: that package ships no __main__, so the
    interpreter refuses it. The real entry point is the `vol` console script
    (console_scripts: vol = volatility3.cli:main). Prefer the one installed
    beside this interpreter, and fall back to calling main() directly so the
    runner still works if the script is missing from PATH.
    """
    bindir = os.path.dirname(os.path.abspath(sys.executable))
    for name in ("vol", "vol.py", "volatility3"):
        cand = os.path.join(bindir, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return [cand]
    return [sys.executable, "-c",
            "import sys; from volatility3.cli import main; sys.exit(main())"]


VOL_CMD = os.environ.get("VOL3_CMD", "").split() or _default_vol_cmd()

app = FastAPI(title="Volatility 3 Runner", version="1.0.0")

# job_id -> Popen
_RUNNING = {}
_RUNNING_LOCK = threading.Lock()

PROGRESS_RE = re.compile(r"Progress:\s*([0-9]+(?:\.[0-9]+)?)")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def ev(kind, **kw):
    kw["t"] = kind
    kw["ts"] = time.time()
    return json.dumps(kw, default=str) + "\n"


def vol_version():
    try:
        import volatility3.framework.constants as c
        return ".".join(str(x) for x in c.VERSION_MAJOR_MINOR_PATCH) if hasattr(
            c, "VERSION_MAJOR_MINOR_PATCH") else str(getattr(c, "PACKAGE_VERSION", "unknown"))
    except Exception:
        try:
            import volatility3
            return getattr(volatility3, "__version__", "unknown")
        except Exception:
            return "unknown"


_PLUGIN_CACHE = {"ts": 0.0, "data": None}


def discover_plugins():
    """Enumerate every plugin the installed volatility3 exposes."""
    if _PLUGIN_CACHE["data"] is not None and time.time() - _PLUGIN_CACHE["ts"] < 600:
        return _PLUGIN_CACHE["data"]

    plugins = []
    try:
        import volatility3.plugins
        from volatility3 import framework
        from volatility3.framework import interfaces

        framework.require_interface_version(2, 0, 0)
        framework.import_files(volatility3.plugins, True)
        found = framework.list_plugins()

        for name, cls in sorted(found.items()):
            doc = (cls.__doc__ or "").strip().split("\n")[0]
            os_family = name.split(".")[0].lower()
            if os_family not in ("windows", "linux", "mac"):
                os_family = "generic"
            reqs = []
            try:
                for r in cls.get_requirements():
                    if isinstance(r, interfaces.configuration.SimpleTypeRequirement) or getattr(
                            r, "name", None):
                        reqs.append({
                            "name": getattr(r, "name", ""),
                            "description": (getattr(r, "description", "") or "").strip(),
                            "optional": bool(getattr(r, "optional", True)),
                            "type": type(r).__name__,
                        })
            except Exception:
                pass
            plugins.append({
                "name": name,
                "description": doc,
                "os": os_family,
                "requirements": [r for r in reqs if r["name"] not in
                                 ("primary", "kernel", "nt_symbols", "memory_layer")],
            })
    except Exception as exc:  # pragma: no cover - defensive
        plugins = []
        _PLUGIN_CACHE["error"] = str(exc)

    _PLUGIN_CACHE["data"] = plugins
    _PLUGIN_CACHE["ts"] = time.time()
    return plugins


def build_argv(image, plugin, args=None, renderer="json", extra_global=None):
    argv = list(VOL_CMD)
    if os.path.isdir(SYMBOLS_DIR):
        argv += ["-s", SYMBOLS_DIR]
    argv += ["-f", image, "-r", renderer]
    for tok in (extra_global or []):
        argv.append(str(tok))
    argv.append(plugin)
    for key, value in (args or {}).items():
        if value is None or value is False or value == "":
            continue
        flag = key if key.startswith("-") else "--" + key.lstrip("-")
        if value is True:
            argv.append(flag)
        else:
            argv += [flag, str(value)]
    return argv


def _pump(stream, kind, q):
    try:
        for line in iter(stream.readline, ""):
            q.put((kind, line.rstrip("\r\n")))
    except Exception as exc:
        q.put((kind, "[runner] stream error: %s" % exc))
    finally:
        try:
            stream.close()
        except Exception:
            pass
        q.put((kind, None))


def execute_stream(job_id, image, plugin, args=None, timeout=None, renderer="json",
                   extra_global=None):
    """Generator yielding NDJSON events for one plugin execution."""
    timeout = timeout or DEFAULT_TIMEOUT
    workdir = os.path.join(ARTIFACT_DIR, str(job_id))
    try:
        os.makedirs(workdir, exist_ok=True)
    except Exception:
        workdir = "/tmp"

    argv = build_argv(image, plugin, args, renderer, extra_global)
    yield ev("status", state="starting", engine=ENGINE, plugin=plugin,
             command=" ".join(shlex.quote(a) for a in argv))

    if not os.path.exists(image):
        yield ev("done", rc=2, error="memory image not found inside runner: %s" % image)
        return

    started = time.time()
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=workdir, bufsize=1, universal_newlines=True, errors="replace",
            start_new_session=True,
        )
    except Exception as exc:
        yield ev("done", rc=127, error="failed to spawn volatility: %s" % exc)
        return

    with _RUNNING_LOCK:
        _RUNNING[job_id] = proc

    q = queue.Queue()
    threading.Thread(target=_pump, args=(proc.stdout, "out", q), daemon=True).start()
    threading.Thread(target=_pump, args=(proc.stderr, "err", q), daemon=True).start()

    out_chunks = []
    err_tail = []
    closed = 0
    last_pct = -1.0
    killed_for_timeout = False

    yield ev("status", state="running")

    while closed < 2:
        if time.time() - started > timeout:
            killed_for_timeout = True
            _kill(proc)
            break
        try:
            kind, line = q.get(timeout=1.0)
        except queue.Empty:
            yield ev("heartbeat", elapsed=round(time.time() - started, 1))
            continue
        if line is None:
            closed += 1
            continue
        if kind == "out":
            out_chunks.append(line)
        else:
            err_tail.append(line)
            if len(err_tail) > 400:
                err_tail.pop(0)
            m = PROGRESS_RE.search(line)
            if m:
                pct = float(m.group(1))
                if pct - last_pct >= 1.0 or pct >= 100.0:
                    last_pct = pct
                    yield ev("progress", pct=pct, line=line)
                continue
            yield ev("log", line=line)

    rc = proc.wait() if not killed_for_timeout else -9
    with _RUNNING_LOCK:
        _RUNNING.pop(job_id, None)

    raw = "\n".join(out_chunks)
    payload = None
    fmt = "text"
    if renderer == "json" and raw.strip():
        try:
            payload = json.loads(raw)
            fmt = "json"
        except Exception as exc:
            yield ev("log", line="[runner] JSON parse failed (%s); returning raw text" % exc)
            payload = raw
    else:
        payload = raw

    artifacts = []
    try:
        for fname in sorted(os.listdir(workdir)):
            full = os.path.join(workdir, fname)
            if os.path.isfile(full):
                artifacts.append({"name": fname, "size": os.path.getsize(full),
                                  "path": full})
    except Exception:
        pass

    yield ev("result", format=fmt, data=payload, artifacts=artifacts)
    yield ev("done",
             rc=rc,
             timed_out=killed_for_timeout,
             duration=round(time.time() - started, 2),
             stderr_tail="\n".join(err_tail[-40:]))


def _kill(proc):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except Exception:
        try:
            proc.terminate()
        except Exception:
            return
    for _ in range(20):
        if proc.poll() is not None:
            return
        time.sleep(0.25)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    with _RUNNING_LOCK:
        active = list(_RUNNING.keys())
    return {
        "ok": True,
        "engine": ENGINE,
        "label": "Volatility 3",
        "version": vol_version(),
        "python": sys.version.split()[0],
        "symbols_dir": SYMBOLS_DIR,
        "symbols_present": os.path.isdir(SYMBOLS_DIR) and bool(os.listdir(SYMBOLS_DIR))
        if os.path.isdir(SYMBOLS_DIR) else False,
        "active_jobs": active,
    }


@app.get("/plugins")
def plugins():
    data = discover_plugins()
    return {"engine": ENGINE, "count": len(data), "plugins": data,
            "error": _PLUGIN_CACHE.get("error")}


@app.post("/identify")
def identify(body: dict = Body(...)):
    """Cheap OS identification: try windows.info, then banners for Linux/Mac."""
    image = body.get("image")
    out = {"engine": ENGINE, "os": None, "details": {}, "banners": []}
    if not image or not os.path.exists(image):
        return JSONResponse({"error": "image not found: %s" % image}, status_code=400)

    def _quick(plugin, timeout=600):
        argv = build_argv(image, plugin, renderer="json")
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=timeout)
            if p.returncode == 0 and p.stdout.strip():
                return json.loads(p.stdout.decode("utf-8", "replace"))
        except Exception:
            return None
        return None

    info = _quick("windows.info.Info")
    if info:
        out["os"] = "windows"
        for row in info:
            key = row.get("Variable") or row.get("Key")
            if key:
                out["details"][str(key)] = row.get("Value")
        return out

    banners = _quick("banners.Banners")
    if banners:
        out["banners"] = banners
        text = json.dumps(banners).lower()
        if "linux version" in text:
            out["os"] = "linux"
        elif "darwin" in text or "xnu" in text:
            out["os"] = "mac"
    return out


@app.post("/run")
def run(body: dict = Body(...)):
    job_id = str(body.get("job_id") or uuid.uuid4())
    image = body.get("image")
    plugin = body.get("plugin")
    args = body.get("args") or {}
    timeout = int(body.get("timeout") or DEFAULT_TIMEOUT)
    renderer = body.get("renderer") or "json"
    extra_global = body.get("global_args") or []

    if not image or not plugin:
        return JSONResponse({"error": "image and plugin are required"}, status_code=400)

    gen = execute_stream(job_id, image, plugin, args, timeout, renderer, extra_global)
    return StreamingResponse(gen, media_type="application/x-ndjson")


@app.post("/cancel/{job_id}")
def cancel(job_id: str):
    with _RUNNING_LOCK:
        proc = _RUNNING.get(job_id)
    if not proc:
        return {"ok": False, "reason": "not running"}
    _kill(proc)
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
