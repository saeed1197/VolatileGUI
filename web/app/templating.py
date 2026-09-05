"""Shared Jinja environment, filters and helpers."""

from __future__ import annotations

import datetime as dt
import html
import json
import re
from pathlib import Path
from typing import Any

from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from . import catalog, config

TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


# ---------------------------------------------------------------------------
# filters
# ---------------------------------------------------------------------------
def fmt_bytes(value: Any) -> str:
    try:
        n = float(value or 0)
    except Exception:
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_dt(value: Any, with_seconds: bool = True) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        return value
    fmt = "%Y-%m-%d %H:%M:%S" if with_seconds else "%Y-%m-%d %H:%M"
    return value.strftime(fmt)


def fmt_ago(value: Any) -> str:
    if not value:
        return "—"
    if isinstance(value, str):
        return value
    delta = dt.datetime.utcnow() - value
    secs = int(delta.total_seconds())
    if secs < 0:
        return "just now"
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    if secs < 86400 * 30:
        return f"{secs // 86400}d ago"
    return value.strftime("%Y-%m-%d")


def fmt_duration(value: Any) -> str:
    try:
        s = float(value or 0)
    except Exception:
        return "—"
    if s < 1:
        return f"{s * 1000:.0f}ms"
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(int(s), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m"
    return f"{m}m {sec}s"


def fmt_num(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except Exception:
        return str(value or 0)


_URL_RE = re.compile(r"(https?://[^\s\"'<>]+)")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PATH_RE = re.compile(r"([A-Za-z]:\\[^\s\"'<>|]+|\\Device\\[^\s\"'<>|]+)")


def highlight(value: Any) -> str:
    """Light syntactic highlighting for cell values and log lines."""
    text = html.escape("" if value is None else str(value))
    text = _URL_RE.sub(r'<span class="hl-url">\1</span>', text)
    text = _IP_RE.sub(r'<span class="hl-ip">\g<0></span>', text)
    text = _PATH_RE.sub(r'<span class="hl-path">\1</span>', text)
    return text


def sev_class(value: str) -> str:
    return f"sev sev-{(value or 'info').lower()}"


def status_class(value: str) -> str:
    return f"st st-{(value or 'queued').lower()}"


def tojson_safe(value: Any) -> str:
    return json.dumps(value, default=str)


templates.env.filters.update({
    "bytes": fmt_bytes,
    "dt": fmt_dt,
    "ago": fmt_ago,
    "duration": fmt_duration,
    "num": fmt_num,
    "highlight": highlight,
    "sev_class": sev_class,
    "status_class": status_class,
    "tojson_safe": tojson_safe,
})

# ---------------------------------------------------------------------------
# inline SVG icon set
#
# These replace the Unicode symbols the UI used to draw.  Emoji/symbol
# characters were a liability: some render as colour emoji and some as plain
# text glyphs that inherit `color`, which is how the preset icons ended up
# invisible on a dark background.  SVG strokes use currentColor, so every icon
# follows the theme exactly and never depends on which fonts are installed.
# ---------------------------------------------------------------------------
_ICON_PATHS: dict[str, str] = {
    # presets
    "zap": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
    "layout": '<rect x="3" y="3" width="18" height="18" rx="2"/>'
              '<line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/>',
    "exchange": '<polyline points="17 2 21 6 17 10"/>'
                '<path d="M3 12V10a4 4 0 0 1 4-4h14"/>'
                '<polyline points="7 22 3 18 7 14"/>'
                '<path d="M21 12v2a4 4 0 0 1-4 4H3"/>',
    "bug": '<rect x="8" y="7" width="8" height="13" rx="4"/>'
           '<path d="M9.5 7a2.5 2.5 0 0 1 5 0"/>'
           '<line x1="8" y1="13" x2="4" y2="13"/><line x1="20" y1="13" x2="16" y2="13"/>'
           '<line x1="8.5" y1="9" x2="5.5" y2="6"/><line x1="15.5" y1="9" x2="18.5" y2="6"/>'
           '<line x1="8.5" y1="18" x2="5.5" y2="21"/><line x1="15.5" y1="18" x2="18.5" y2="21"/>',
    "anchor": '<circle cx="12" cy="5" r="3"/><line x1="12" y1="22" x2="12" y2="8"/>'
              '<path d="M5 12H2a10 10 0 0 0 20 0h-3"/>',
    "key": '<circle cx="7.5" cy="15.5" r="4.5"/>'
           '<line x1="10.8" y1="12.2" x2="21" y2="2"/>'
           '<line x1="18" y1="5" x2="20.5" y2="7.5"/>'
           '<line x1="15.5" y1="7.5" x2="18" y2="10"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><polyline points="12 7 12 12 15.5 14"/>',
    "file": '<path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>'
            '<polyline points="13 2 13 9 20 9"/>',
    "target": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/>'
              '<circle cx="12" cy="12" r="1.4"/>',
    # categories
    "gear": '<circle cx="12" cy="12" r="3.2"/>'
            '<path d="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3'
            'M5.2 5.2l2.1 2.1M16.7 16.7l2.1 2.1M18.8 5.2l-2.1 2.1M7.3 16.7l-2.1 2.1"/>',
    "cpu": '<rect x="5" y="5" width="14" height="14" rx="2"/>'
           '<rect x="9.5" y="9.5" width="5" height="5"/>'
           '<path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3"/>',
    "list": '<line x1="9" y1="6" x2="20" y2="6"/><line x1="9" y1="12" x2="20" y2="12"/>'
            '<line x1="9" y1="18" x2="20" y2="18"/>'
            '<circle cx="4.5" cy="6" r="1.1"/><circle cx="4.5" cy="12" r="1.1"/>'
            '<circle cx="4.5" cy="18" r="1.1"/>',
    "layers": '<polygon points="12 2.5 2.5 7.5 12 12.5 21.5 7.5 12 2.5"/>'
              '<polyline points="2.5 16.5 12 21.5 21.5 16.5"/>'
              '<polyline points="2.5 12 12 17 21.5 12"/>',
    "sparkle": '<path d="M12 3l1.9 5.6L19.5 10.5l-5.6 1.9L12 18l-1.9-5.6L4.5 10.5l5.6-1.9z"/>',
    "dot": '<circle cx="12" cy="12" r="3.6"/>',
    # navigation
    "activity": '<polyline points="22 12 17.5 12 14.5 20 9.5 4 6.5 12 2 12"/>',
    "database": '<ellipse cx="12" cy="5.5" rx="8.5" ry="3"/>'
                '<path d="M3.5 5.5v13c0 1.66 3.8 3 8.5 3s8.5-1.34 8.5-3v-13"/>'
                '<path d="M3.5 12c0 1.66 3.8 3 8.5 3s8.5-1.34 8.5-3"/>',
    "folder": '<path d="M21.5 19a2 2 0 0 1-2 2h-15a2 2 0 0 1-2-2V5.5a2 2 0 0 1 2-2h4.5l2 3h8.5'
              'a2 2 0 0 1 2 2z"/>',
    "flag": '<path d="M4.5 14.5s1-1 4-1 5 2 8 2 3.5-1 3.5-1V4s-1 1-3.5 1-5-2-8-2-4 1-4 1z"/>'
            '<line x1="4.5" y1="21.5" x2="4.5" y2="14.5"/>',
    "file-text": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>'
                 '<polyline points="14 2 14 8 20 8"/>'
                 '<line x1="15.5" y1="13" x2="8.5" y2="13"/>'
                 '<line x1="15.5" y1="17" x2="8.5" y2="17"/>',
    "grid": '<rect x="3" y="3" width="7.5" height="7.5" rx="1"/>'
            '<rect x="13.5" y="3" width="7.5" height="7.5" rx="1"/>'
            '<rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1"/>'
            '<rect x="3" y="13.5" width="7.5" height="7.5" rx="1"/>',
    "sliders": '<line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/>'
               '<line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/>'
               '<line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/>'
               '<line x1="1.5" y1="14" x2="6.5" y2="14"/>'
               '<line x1="9.5" y1="8" x2="14.5" y2="8"/>'
               '<line x1="17.5" y1="16" x2="22.5" y2="16"/>',
    "external": '<path d="M18 13.5V19a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h5.5"/>'
                '<polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
    # theme toggle
    "sun": '<circle cx="12" cy="12" r="4.5"/>'
           '<path d="M12 1.5v2.5M12 20v2.5M3.6 3.6l1.8 1.8M18.6 18.6l1.8 1.8'
           'M1.5 12h2.5M20 12h2.5M3.6 20.4l1.8-1.8M18.6 5.4l1.8-1.8"/>',
    "moon": '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
}


def icon(name: str, cls: str = "") -> Markup:
    """Inline SVG by name. Strokes use currentColor, so it always matches the
    surrounding text colour in either theme."""
    body = _ICON_PATHS.get(name)
    if body is None:
        body = _ICON_PATHS["dot"]
    classes = ("icon " + cls).strip()
    return Markup(
        f'<svg class="{classes}" viewBox="0 0 24 24" fill="none" '
        f'stroke="currentColor" stroke-width="1.9" stroke-linecap="round" '
        f'stroke-linejoin="round" aria-hidden="true" focusable="false">{body}</svg>'
    )


templates.env.globals.update({
    "APP_NAME": config.APP_NAME,
    "APP_TAGLINE": config.APP_TAGLINE,
    "VERSION": config.VERSION,
    "ENGINES": config.ENGINES,
    "PRESETS": catalog.PRESETS,
    "CATEGORY_ICONS": catalog.CATEGORY_ICONS,
    "icon": icon,
    "now": lambda: dt.datetime.utcnow(),
})
