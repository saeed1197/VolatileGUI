#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Volatility 2.6.1 execution shim (Python 2.7).

Implements exactly the same HTTP contract as the Volatility 3 runner so the
web platform can drive either engine through a single client:

    GET  /health              -> engine metadata
    GET  /plugins             -> parsed `vol.py --info` catalog
    POST /identify            -> imageinfo -> suggested profiles
    POST /run                 -> NDJSON event stream of a plugin execution
    POST /cancel/<job_id>     -> kill a running execution

Written to be syntax-compatible with both Python 2 and 3 (it *runs* under 2.7
inside its container), and to depend on nothing outside the standard library.
"""

from __future__ import print_function

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import uuid

try:  # Python 2
    from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
    from SocketServer import ThreadingMixIn
    from urlparse import urlparse
except ImportError:  # Python 3 (used for linting / local smoke tests)
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
    from urllib.parse import urlparse

ENGINE = "vol2"
PORT = int(os.environ.get("RUNNER_PORT", "9002"))
VOL2_HOME = os.environ.get("VOL2_HOME", "/opt/volatility")
VOL_PY = os.path.join(VOL2_HOME, "vol.py")
PLUGIN_DIR = os.environ.get("VOL2_PLUGINS", "/profiles")
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "/artifacts")
DEFAULT_TIMEOUT = int(os.environ.get("RUNNER_TIMEOUT", "7200"))
PYTHON2 = os.environ.get("VOL2_PYTHON", "python2")

_RUNNING = {}
_LOCK = threading.Lock()

_INFO_CACHE = {"ts": 0, "data": None}

SUGGESTED_RE = re.compile(r"Suggested Profile\(s\)\s*:\s*(.+)")
PROGRESS_RE = re.compile(r"([0-9]{1,3}(?:\.[0-9]+)?)%")

LINUX_PREFIXES = ("linux_",)
MAC_PREFIXES = ("mac_",)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def ev(kind, **kw):
    kw["t"] = kind
    kw["ts"] = time.time()
    return json.dumps(kw, default=str) + "\n"


def base_argv():
    argv = [PYTHON2, VOL_PY]
    if PLUGIN_DIR and os.path.isdir(PLUGIN_DIR) and os.listdir(PLUGIN_DIR):
        argv += ["--plugins=%s" % PLUGIN_DIR]
    return argv


def vol_version():
    try:
        p = subprocess.Popen(base_argv() + ["--help"], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        out = p.communicate()[0]
        if not isinstance(out, str):
            out = out.decode("utf-8", "replace")
        m = re.search(r"Volatility Framework\s+([0-9][0-9a-zA-Z.\-]*)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "2.6.1"


def parse_info(text):
    """Parse the section-per-block layout of `vol.py --info`."""
    sections = {}
    current = None
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if (stripped and idx + 1 < len(lines)
                and set(lines[idx + 1].strip()) == set("-")
                and len(lines[idx + 1].strip()) >= 3):
            current = stripped
            sections[current] = []
            continue
        if stripped and set(stripped) == set("-"):
            continue
        if current is None or not stripped:
            continue
        parts = stripped.split(" - ", 1)
        name = parts[0].strip()
        desc = parts[1].strip() if len(parts) > 1 else ""
        if not name or " " in name:
            continue
        sections[current].append({"name": name, "description": desc})
    return sections


def guess_os(name):
    if name.startswith(LINUX_PREFIXES):
        return "linux"
    if name.startswith(MAC_PREFIXES):
        return "mac"
    return "windows"


def discover():
    if _INFO_CACHE["data"] is not None and time.time() - _INFO_CACHE["ts"] < 600:
        return _INFO_CACHE["data"]
    result = {"plugins": [], "profiles": [], "address_spaces": [], "scanners": []}
    try:
        p = subprocess.Popen(base_argv() + ["--info"], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        out, err = p.communicate()
        if not isinstance(out, str):
            out = out.decode("utf-8", "replace")
        sections = parse_info(out)
        for header, items in sections.items():
            low = header.lower()
            if low.startswith("plugins"):
                for it in items:
                    it["os"] = guess_os(it["name"])
                result["plugins"] = items
            elif low.startswith("profiles"):
                result["profiles"] = items
            elif "address space" in low:
                result["address_spaces"] = items
            elif "scanner" in low:
                result["scanners"] = items
    except Exception as exc:
        result["error"] = str(exc)
    _INFO_CACHE["data"] = result
    _INFO_CACHE["ts"] = time.time()
    return result


def build_argv(image, plugin, profile=None, args=None, renderer="json"):
    argv = base_argv()
    argv += ["-f", image]
    if profile:
        argv.append("--profile=%s" % profile)
    if renderer == "json":
        argv.append("--output=json")
    argv.append(plugin)
    for key, value in (args or {}).items():
        if value is None or value is False or value == "":
            continue
        flag = key if key.startswith("-") else "--" + key.lstrip("-")
        if value is True:
            argv.append(flag)
        else:
            argv.append("%s=%s" % (flag, value))
    return argv


def _pump(fileobj, kind, sink):
    """Read a stream, splitting on both \\n and \\r (progress bars use \\r)."""
    buf = ""
    try:
        while True:
            chunk = fileobj.read(1)
            if not chunk:
                break
            if not isinstance(chunk, str):
                chunk = chunk.decode("utf-8", "replace")
            if chunk in ("\n", "\r"):
                if buf:
                    sink.append((kind, buf))
                    buf = ""
            else:
                buf += chunk
                if len(buf) > 65536:
                    sink.append((kind, buf))
                    buf = ""
    except Exception as exc:
        sink.append((kind, "[runner] stream error: %s" % exc))
    finally:
        if buf:
            sink.append((kind, buf))
        sink.append((kind, None))


class Sink(object):
    """Tiny thread-safe queue (avoids Queue import differences)."""

    def __init__(self):
        self._items = []
        self._cv = threading.Condition()

    def append(self, item):
        with self._cv:
            self._items.append(item)
            self._cv.notify()

    def get(self, timeout=1.0):
        with self._cv:
            if not self._items:
                self._cv.wait(timeout)
            if not self._items:
                return None
            return self._items.pop(0)


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


def execute_stream(job_id, image, plugin, profile=None, args=None, timeout=None,
                   renderer="json"):
    timeout = timeout or DEFAULT_TIMEOUT
    workdir = os.path.join(ARTIFACT_DIR, str(job_id))
    try:
        if not os.path.isdir(workdir):
            os.makedirs(workdir)
    except Exception:
        workdir = "/tmp"

    attempts = [renderer]
    if renderer == "json":
        attempts.append("text")   # many vol2 plugins only implement render_text

    last_events = []
    for attempt_no, rend in enumerate(attempts):
        argv = build_argv(image, plugin, profile, args, rend)
        yield ev("status", state="starting", engine=ENGINE, plugin=plugin,
                 profile=profile, renderer=rend, command=" ".join(argv))

        if not os.path.exists(image):
            yield ev("done", rc=2,
                     error="memory image not found inside runner: %s" % image)
            return

        started = time.time()
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, cwd=workdir,
                                    preexec_fn=os.setsid)
        except Exception as exc:
            yield ev("done", rc=127, error="failed to spawn volatility: %s" % exc)
            return

        with _LOCK:
            _RUNNING[job_id] = proc

        sink = Sink()
        t1 = threading.Thread(target=_pump, args=(proc.stdout, "out", sink))
        t2 = threading.Thread(target=_pump, args=(proc.stderr, "err", sink))
        t1.daemon = t2.daemon = True
        t1.start()
        t2.start()

        out_chunks = []
        err_tail = []
        closed = 0
        last_pct = -1.0
        timed_out = False

        yield ev("status", state="running")

        while closed < 2:
            if time.time() - started > timeout:
                timed_out = True
                _kill(proc)
                break
            item = sink.get(timeout=1.0)
            if item is None:
                yield ev("heartbeat", elapsed=round(time.time() - started, 1))
                continue
            kind, line = item
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

        rc = proc.wait() if not timed_out else -9
        with _LOCK:
            _RUNNING.pop(job_id, None)

        raw = "\n".join(out_chunks)
        stderr_text = "\n".join(err_tail)

        unsupported = ("does not support" in stderr_text.lower()
                       or "unified output" in stderr_text.lower()
                       or "no such option" in stderr_text.lower())
        if (rend == "json" and (unsupported or (rc != 0 and not raw.strip()))
                and attempt_no + 1 < len(attempts) and not timed_out):
            yield ev("log", line="[runner] plugin has no JSON renderer - "
                                 "retrying with text output")
            continue

        payload = raw
        fmt = "text"
        if rend == "json" and raw.strip():
            try:
                payload = json.loads(raw)
                fmt = "json"
            except Exception as exc:
                yield ev("log", line="[runner] JSON parse failed (%s)" % exc)
                payload = raw

        artifacts = []
        try:
            for fname in sorted(os.listdir(workdir)):
                full = os.path.join(workdir, fname)
                if os.path.isfile(full):
                    artifacts.append({"name": fname,
                                      "size": os.path.getsize(full),
                                      "path": full})
        except Exception:
            pass

        yield ev("result", format=fmt, data=payload, artifacts=artifacts)
        yield ev("done", rc=rc, timed_out=timed_out,
                 duration=round(time.time() - started, 2),
                 stderr_tail="\n".join(err_tail[-40:]))
        return

    for e in last_events:
        yield e


def identify(image):
    """Run imageinfo and pull out the suggested profiles."""
    out = {"engine": ENGINE, "os": "windows", "profiles": [], "details": {},
           "raw": ""}
    argv = base_argv() + ["-f", image, "imageinfo"]
    try:
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if not isinstance(stdout, str):
            stdout = stdout.decode("utf-8", "replace")
        out["raw"] = stdout
        m = SUGGESTED_RE.search(stdout)
        if m:
            raw = m.group(1)
            raw = re.sub(r"\([^)]*\)", "", raw)
            out["profiles"] = [x.strip() for x in raw.split(",") if x.strip()]
        for line in stdout.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip()
                if k and len(k) < 60:
                    out["details"][k] = v.strip()
    except Exception as exc:
        out["error"] = str(exc)
    return out


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "Vol2Runner/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[vol2-runner] %s - %s\n" % (self.address_string(), fmt % args))

    # -- utilities ---------------------------------------------------------
    def _json(self, obj, code=200):
        body = json.dumps(obj, default=str)
        if not isinstance(body, bytes):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        if not isinstance(raw, str):
            raw = raw.decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    # -- routes ------------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            with _LOCK:
                active = list(_RUNNING.keys())
            info = discover()
            self._json({
                "ok": os.path.exists(VOL_PY),
                "engine": ENGINE,
                "label": "Volatility 2",
                "version": vol_version(),
                "python": sys.version.split()[0],
                "vol_home": VOL2_HOME,
                "plugin_dir": PLUGIN_DIR,
                "profile_count": len(info.get("profiles", [])),
                "active_jobs": active,
            })
        elif path == "/plugins":
            info = discover()
            self._json({
                "engine": ENGINE,
                "count": len(info.get("plugins", [])),
                "plugins": info.get("plugins", []),
                "profiles": [p["name"] for p in info.get("profiles", [])],
                "error": info.get("error"),
            })
        elif path == "/profiles":
            info = discover()
            self._json({"profiles": info.get("profiles", [])})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read_body()

        if path == "/identify":
            image = body.get("image")
            if not image or not os.path.exists(image):
                self._json({"error": "image not found: %s" % image}, 400)
                return
            self._json(identify(image))
            return

        if path.startswith("/cancel/"):
            job_id = path.split("/cancel/", 1)[1]
            with _LOCK:
                proc = _RUNNING.get(job_id)
            if not proc:
                self._json({"ok": False, "reason": "not running"})
                return
            _kill(proc)
            self._json({"ok": True})
            return

        if path == "/run":
            image = body.get("image")
            plugin = body.get("plugin")
            if not image or not plugin:
                self._json({"error": "image and plugin are required"}, 400)
                return
            job_id = str(body.get("job_id") or uuid.uuid4())
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            try:
                for chunk in execute_stream(job_id, image, plugin,
                                            body.get("profile"),
                                            body.get("args") or {},
                                            int(body.get("timeout") or DEFAULT_TIMEOUT),
                                            body.get("renderer") or "json"):
                    data = chunk if isinstance(chunk, bytes) else chunk.encode("utf-8")
                    self.wfile.write(data)
                    self.wfile.flush()
            except Exception as exc:
                try:
                    self.wfile.write(ev("done", rc=1, error=str(exc)).encode("utf-8"))
                except Exception:
                    pass
            return

        self._json({"error": "not found"}, 404)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    sys.stderr.write("[vol2-runner] volatility home=%s exists=%s\n"
                     % (VOL2_HOME, os.path.exists(VOL_PY)))
    server = ThreadedHTTPServer(("0.0.0.0", PORT), Handler)
    sys.stderr.write("[vol2-runner] listening on 0.0.0.0:%d\n" % PORT)
    server.serve_forever()


if __name__ == "__main__":
    main()
