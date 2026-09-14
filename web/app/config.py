"""Runtime configuration, read from the environment with sane local defaults."""

import os
from pathlib import Path


def _path(env_key: str, default: str) -> Path:
    p = Path(os.environ.get(env_key, default))
    p.mkdir(parents=True, exist_ok=True)
    return p


APP_NAME = "VolatileGUI"
APP_TAGLINE = "Volatility 2 & 3 memory analysis platform"
VERSION = "1.0.0"

DATA_DIR = _path("MF_DATA_DIR", "./data")
EVIDENCE_DIR = _path("MF_EVIDENCE_DIR", "./evidence")

ARTIFACT_DIR = _path("MF_ARTIFACT_DIR", "./artifacts")
LOG_DIR = DATA_DIR / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR = DATA_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR = DATA_DIR / "results"
RESULT_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "volatilegui.sqlite3"
DB_URL = os.environ.get("MF_DB_URL", f"sqlite:///{DB_PATH}")

ENGINES = {
    "vol3": {
        "key": "vol3",
        "label": "Volatility 3",
        "url": os.environ.get("MF_VOL3_URL", "http://vol3:9003"),
        "blurb": "Modern engine. No profiles - uses symbol tables (ISF). "
                 "Best coverage for Windows 10/11 and recent Linux kernels.",
    },
    "vol2": {
        "key": "vol2",
        "label": "Volatility 2",
        "url": os.environ.get("MF_VOL2_URL", "http://vol2:9002"),
        "blurb": "Legacy engine (Python 2.7). Profile-based. Still the best "
                 "choice for XP/Vista/7 images and a few plugins with no vol3 port.",
    },
}

WORKERS = int(os.environ.get("MF_WORKERS", "2"))
MAX_UPLOAD_BYTES = int(float(os.environ.get("MF_MAX_UPLOAD_GB", "64")) * (1024 ** 3))
JOB_TIMEOUT = int(os.environ.get("MF_JOB_TIMEOUT", "7200"))
SECRET = os.environ.get("MF_SECRET", "dev-secret-change-me")
TZ = os.environ.get("TZ", "UTC")

# How many result rows we keep inline in the DB row-preview (full result always
# lives on disk as JSON).
PREVIEW_ROWS = int(os.environ.get("MF_PREVIEW_ROWS", "5000"))

IMAGE_SUFFIXES = {
    ".raw", ".mem", ".vmem", ".dmp", ".bin", ".img", ".lime", ".core",
    ".vmss", ".vmsn", ".hpak", ".crash", ".elf", ".aff4", ".sav", ".dump",
    ".001", ".e01",
}
