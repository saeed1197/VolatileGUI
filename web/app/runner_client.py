"""HTTP client for the two Volatility runner containers."""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

import httpx

from . import config

_CACHE: Dict[str, dict] = {}
_CACHE_LOCK = threading.Lock()
HEALTH_TTL = 20
PLUGIN_TTL = 600


class RunnerError(RuntimeError):
    pass


def base_url(engine: str) -> str:
    cfg = config.ENGINES.get(engine)
    if not cfg:
        raise RunnerError(f"unknown engine: {engine}")
    return cfg["url"].rstrip("/")


def _cached(key: str, ttl: int):
    with _CACHE_LOCK:
        item = _CACHE.get(key)
        if item and time.time() - item["ts"] < ttl:
            return item["data"]
    return None


def _store(key: str, data):
    with _CACHE_LOCK:
        _CACHE[key] = {"ts": time.time(), "data": data}
    return data


def invalidate(engine: Optional[str] = None) -> None:
    with _CACHE_LOCK:
        if engine is None:
            _CACHE.clear()
        else:
            for k in [k for k in _CACHE if k.startswith(engine + ":")]:
                _CACHE.pop(k, None)


def health(engine: str, force: bool = False) -> dict:
    key = f"{engine}:health"
    if not force:
        hit = _cached(key, HEALTH_TTL)
        if hit is not None:
            return hit
    try:
        r = httpx.get(f"{base_url(engine)}/health", timeout=10.0)
        r.raise_for_status()
        data = r.json()
        data["reachable"] = True
    except Exception as exc:
        data = {
            "ok": False, "reachable": False, "engine": engine,
            "label": config.ENGINES.get(engine, {}).get("label", engine),
            "error": f"{type(exc).__name__}: {exc}",
        }
    return _store(key, data)


def plugins(engine: str, force: bool = False) -> List[dict]:
    key = f"{engine}:plugins"
    if not force:
        hit = _cached(key, PLUGIN_TTL)
        if hit is not None:
            return hit
    try:
        r = httpx.get(f"{base_url(engine)}/plugins", timeout=180.0)
        r.raise_for_status()
        payload = r.json()
        data = payload.get("plugins", [])
        if engine == "vol2" and payload.get("profiles"):
            _store("vol2:profiles", payload["profiles"])
    except Exception:
        data = []
    return _store(key, data)


def vol2_profiles(force: bool = False) -> List[str]:
    hit = _cached("vol2:profiles", PLUGIN_TTL)
    if hit is not None and not force:
        return hit
    try:
        r = httpx.get(f"{base_url('vol2')}/profiles", timeout=120.0)
        r.raise_for_status()
        data = [p["name"] for p in r.json().get("profiles", [])]
    except Exception:
        data = []
    return _store("vol2:profiles", data)


def identify(engine: str, image_path: str, timeout: float = 1800.0) -> dict:
    try:
        r = httpx.post(f"{base_url(engine)}/identify",
                       json={"image": image_path}, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "engine": engine}


def cancel(engine: str, job_uid: str) -> dict:
    try:
        r = httpx.post(f"{base_url(engine)}/cancel/{job_uid}", timeout=15.0)
        return r.json()
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def stream_run(engine: str, payload: Dict[str, Any],
               timeout: Optional[float] = None) -> Iterator[dict]:
    """Yield decoded NDJSON events from a runner's /run endpoint."""
    read_timeout = timeout or (config.JOB_TIMEOUT + 120)
    limits = httpx.Timeout(connect=15.0, read=read_timeout,
                           write=60.0, pool=30.0)
    with httpx.Client(timeout=limits) as client:
        with client.stream("POST", f"{base_url(engine)}/run", json=payload) as resp:
            if resp.status_code >= 400:
                body = resp.read().decode("utf-8", "replace")
                raise RunnerError(f"runner returned HTTP {resp.status_code}: {body[:500]}")
            for line in resp.iter_lines():
                if not line:
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    yield {"t": "log", "line": line}


def engine_status() -> List[dict]:
    """Health of both engines, for the dashboard/settings pages."""
    out = []
    for key, cfg in config.ENGINES.items():
        h = health(key)
        out.append({
            "key": key,
            "label": cfg["label"],
            "blurb": cfg["blurb"],
            "url": cfg["url"],
            "online": bool(h.get("reachable") and h.get("ok", True)),
            "version": h.get("version", "?"),
            "python": h.get("python", "?"),
            "error": h.get("error"),
            "detail": h,
        })
    return out
