"""Database bootstrap + tiny helpers."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from . import config
from .models import Audit, Base, Setting

engine = create_engine(
    config.DB_URL,
    future=True,
    connect_args={"check_same_thread": False, "timeout": 30},
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _rec):
    cur = dbapi_conn.cursor()
    # WAL keeps the worker threads from blocking the web request threads.
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA busy_timeout=30000")
    cur.close()


SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(engine)


@contextmanager
def session_scope() -> Iterator[Session]:
    s = SessionLocal()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_session() -> Iterator[Session]:
    """FastAPI dependency."""
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()


def audit(action: str, target: str = "", detail: str = "") -> None:
    try:
        with session_scope() as s:
            s.add(Audit(action=action, target=str(target)[:200], detail=detail[:4000]))
    except Exception:
        pass


DEFAULT_SETTINGS = {
    "default_engine": "vol3",
    "auto_triage": "1",
    "auto_identify": "1",
    "job_timeout": str(config.JOB_TIMEOUT),
    "hide_empty_results": "0",
    "organisation": "",
    "analyst": "",
}


def get_setting(key: str, default: str = "") -> str:
    with session_scope() as s:
        row = s.get(Setting, key)
        if row is not None:
            return row.value
    return DEFAULT_SETTINGS.get(key, default)


def all_settings() -> dict:
    out = dict(DEFAULT_SETTINGS)
    with session_scope() as s:
        for row in s.scalars(select(Setting)):
            out[row.key] = row.value
    return out


def set_setting(key: str, value: str) -> None:
    with session_scope() as s:
        row = s.get(Setting, key)
        if row is None:
            s.add(Setting(key=key, value=value))
        else:
            row.value = value
