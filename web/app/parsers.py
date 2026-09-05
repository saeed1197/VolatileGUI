"""
Normalise Volatility 2 and Volatility 3 output into one table shape.

    {
      "format": "table" | "text",
      "columns": ["PID", "PPID", ...],
      "rows": [[4, 0, ...], ...],
      "row_count": 123,
      "text": "..."            # only when format == "text"
    }

Everything downstream (UI tables, CSV export, the triage engine, run
comparison) speaks this shape and never has to know which engine produced it.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

TREE_KEY = "__children"
DEPTH_COL = "Depth"


# ---------------------------------------------------------------------------
# vol3
# ---------------------------------------------------------------------------
def _flatten_vol3(nodes: Iterable[dict], depth: int = 0,
                  out: Optional[List[dict]] = None) -> List[dict]:
    if out is None:
        out = []
    for node in nodes:
        if not isinstance(node, dict):
            out.append({"Value": node})
            continue
        row = {k: v for k, v in node.items() if k != TREE_KEY}
        children = node.get(TREE_KEY) or []
        if children or depth:
            row[DEPTH_COL] = depth
        out.append(row)
        if children:
            _flatten_vol3(children, depth + 1, out)
    return out


def _columns_from_dicts(rows: List[dict]) -> List[str]:
    cols: List[str] = []
    seen = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                cols.append(key)
    # Put the tree depth column first when present, it drives the indentation.
    if DEPTH_COL in cols:
        cols.remove(DEPTH_COL)
        cols.insert(0, DEPTH_COL)
    return cols


def parse_vol3(data: Any) -> Dict[str, Any]:
    if isinstance(data, str):
        return {"format": "text", "columns": [], "rows": [], "row_count": 0,
                "text": data}
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return {"format": "text", "columns": [], "rows": [], "row_count": 0,
                "text": str(data)}

    flat = _flatten_vol3(data)
    cols = _columns_from_dicts(flat)
    rows = [[_scalar(r.get(c)) for c in cols] for r in flat]
    return {"format": "table", "columns": cols, "rows": rows,
            "row_count": len(rows), "text": ""}


# ---------------------------------------------------------------------------
# vol2
# ---------------------------------------------------------------------------
def parse_vol2(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict) and "columns" in data and "rows" in data:
        cols = [str(c) for c in data.get("columns") or []]
        rows = [[_scalar(v) for v in row] for row in (data.get("rows") or [])]
        return {"format": "table", "columns": cols, "rows": rows,
                "row_count": len(rows), "text": ""}
    if isinstance(data, list) and data and isinstance(data[0], dict):
        cols = _columns_from_dicts(data)
        rows = [[_scalar(r.get(c)) for c in cols] for r in data]
        return {"format": "table", "columns": cols, "rows": rows,
                "row_count": len(rows), "text": ""}
    if isinstance(data, str):
        parsed = parse_text_table(data)
        if parsed:
            return parsed
        return {"format": "text", "columns": [], "rows": [], "row_count": 0,
                "text": data}
    return {"format": "text", "columns": [], "rows": [], "row_count": 0,
            "text": str(data)}


# ---------------------------------------------------------------------------
# text fallback: vol2 plugins with no JSON renderer print an aligned table
# ---------------------------------------------------------------------------
_SEP_RE = re.compile(r"^-{2,}(\s+-{2,})+\s*$")


def parse_text_table(text: str) -> Optional[Dict[str, Any]]:
    """Recover columns from Volatility 2's classic `---- ----` header rule."""
    lines = [ln.rstrip() for ln in (text or "").splitlines()]
    sep_idx = None
    for idx, line in enumerate(lines):
        if _SEP_RE.match(line.strip()) and idx > 0 and lines[idx - 1].strip():
            sep_idx = idx
            break
    if sep_idx is None:
        return None

    rule = lines[sep_idx]
    header = lines[sep_idx - 1]

    spans: List[tuple] = []
    for m in re.finditer(r"-+", rule):
        spans.append((m.start(), m.end()))
    if len(spans) < 2:
        return None

    def slice_row(line: str) -> List[str]:
        vals = []
        for i, (start, end) in enumerate(spans):
            stop = len(line) if i == len(spans) - 1 else spans[i + 1][0]
            vals.append(line[start:stop].strip() if start < len(line) else "")
        return vals

    columns = [c if c else f"col{i}" for i, c in enumerate(slice_row(header))]
    rows = []
    for line in lines[sep_idx + 1:]:
        if not line.strip():
            continue
        if _SEP_RE.match(line.strip()):
            continue
        rows.append(slice_row(line))
    if not rows:
        return None
    return {"format": "table", "columns": columns, "rows": rows,
            "row_count": len(rows), "text": text}


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------
def normalize(engine: str, fmt: str, data: Any) -> Dict[str, Any]:
    if fmt == "json":
        return parse_vol3(data) if engine == "vol3" else parse_vol2(data)
    if isinstance(data, str):
        table = parse_text_table(data)
        if table:
            return table
        return {"format": "text", "columns": [], "rows": [], "row_count": 0,
                "text": data}
    return parse_vol3(data) if engine == "vol3" else parse_vol2(data)


def _scalar(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, dict) and set(value) == {"__type", "value"}:
        return value.get("value")
    return str(value)


# ---------------------------------------------------------------------------
# accessors used by the triage engine
# ---------------------------------------------------------------------------
def to_dicts(norm: Dict[str, Any], limit: Optional[int] = None) -> List[Dict[str, Any]]:
    cols = norm.get("columns") or []
    rows = norm.get("rows") or []
    if limit:
        rows = rows[:limit]
    return [dict(zip(cols, row)) for row in rows]


_ALIASES = {
    "pid": ("pid", "process id", "processid"),
    "ppid": ("ppid", "parent pid", "parentpid", "parent"),
    "name": ("imagefilename", "image file name", "name", "process", "comm",
             "processname", "file name", "imagename"),
    "path": ("path", "imagepathname", "image path name", "fullpath", "file path",
             "filepath", "loadpath"),
    "cmdline": ("args", "cmdline", "command line", "commandline", "arguments"),
    "createtime": ("createtime", "create time", "start time", "starttime",
                   "createdtime", "starttimestamp"),
    "exittime": ("exittime", "exit time"),
    "threads": ("threads", "thds"),
    "handles": ("handles", "hnds"),
    "protection": ("protection", "protect", "prot"),
    "localaddr": ("localaddr", "local address", "localaddress", "laddr", "local ip"),
    "localport": ("localport", "local port", "lport"),
    "foreignaddr": ("foreignaddr", "foreign address", "remoteaddr",
                    "remote address", "faddr", "remote ip"),
    "foreignport": ("foreignport", "foreign port", "remoteport", "rport"),
    "state": ("state", "status"),
    "proto": ("proto", "protocol", "offset(v)proto", "af"),
    "owner": ("owner", "user", "username", "uid"),
    "session": ("sessionid", "session id", "session"),
    "wow64": ("wow64",),
    "hidden": ("hidden",),
    "file_output": ("file output", "fileoutput", "dumped"),
    "start": ("start", "startaddress", "start address", "base", "startvpn"),
    "module": ("module", "modulename", "driver", "owner"),
}


def norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def field(row: Dict[str, Any], logical: str, default: Any = "") -> Any:
    """Case/format-insensitive column lookup across both engines."""
    wanted = _ALIASES.get(logical, (logical,))
    wanted_norm = {norm_key(w) for w in wanted}
    for key, value in row.items():
        if norm_key(key) in wanted_norm:
            return value
    return default


def as_int(value: Any, default: int = -1) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, str):
            value = value.strip()
            if not value:
                return default
            if value.lower().startswith("0x"):
                return int(value, 16)
        return int(float(value))
    except Exception:
        return default


def as_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)
