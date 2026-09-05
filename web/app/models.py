"""SQLAlchemy models. SQLite-backed, single file, no external DB service."""

from __future__ import annotations

import datetime as dt
import json
from typing import Any, Optional

from sqlalchemy import (
    JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String,
    Text, func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Case(Base):
    """A grouping of evidence — an incident, an exam, a CTF box."""
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    analyst: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(32), default="open")  # open|closed
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    evidence: Mapped[list["Evidence"]] = relationship(
        back_populates="case", cascade="all, delete-orphan")


class Evidence(Base):
    """One memory image."""
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    case_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)

    name: Mapped[str] = mapped_column(String(255), index=True)
    filename: Mapped[str] = mapped_column(String(255))
    path: Mapped[str] = mapped_column(String(1024))         # path inside containers
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    md5: Mapped[str] = mapped_column(String(32), default="")
    hash_state: Mapped[str] = mapped_column(String(24), default="pending")

    source: Mapped[str] = mapped_column(String(32), default="upload")  # upload|scan
    notes: Mapped[str] = mapped_column(Text, default="")

    detected_os: Mapped[str] = mapped_column(String(32), default="")
    vol2_profile: Mapped[str] = mapped_column(String(120), default="")
    vol2_profile_candidates: Mapped[Any] = mapped_column(JSON, default=list)
    identify_state: Mapped[str] = mapped_column(String(24), default="none")
    identify_detail: Mapped[Any] = mapped_column(JSON, default=dict)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    case: Mapped[Optional[Case]] = relationship(back_populates="evidence")
    jobs: Mapped[list["Job"]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan")

    @property
    def size_human(self) -> str:
        n = float(self.size or 0)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024 or unit == "TB":
                return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
            n /= 1024
        return f"{n:.1f} TB"


class Batch(Base):
    """A group of jobs launched together (a preset run or a multi-plugin run)."""
    __tablename__ = "batches"

    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    engine: Mapped[str] = mapped_column(String(16), default="vol3")
    preset: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    jobs: Mapped[list["Job"]] = relationship(back_populates="batch")


class Job(Base):
    """One plugin execution."""
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(36), index=True, unique=True)
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True)
    batch_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("batches.id", ondelete="SET NULL"), nullable=True, index=True)

    engine: Mapped[str] = mapped_column(String(16), index=True)     # vol2 | vol3
    plugin: Mapped[str] = mapped_column(String(160), index=True)
    plugin_label: Mapped[str] = mapped_column(String(160), default="")
    family: Mapped[str] = mapped_column(String(48), default="", index=True)
    args: Mapped[Any] = mapped_column(JSON, default=dict)
    profile: Mapped[str] = mapped_column(String(120), default="")

    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    # queued | running | success | failed | cancelled | empty
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    rc: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    error: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    duration: Mapped[float] = mapped_column(Float, default=0.0)

    row_count: Mapped[int] = mapped_column(Integer, default=0)
    columns: Mapped[Any] = mapped_column(JSON, default=list)
    result_format: Mapped[str] = mapped_column(String(16), default="")
    result_path: Mapped[str] = mapped_column(String(1024), default="")
    log_path: Mapped[str] = mapped_column(String(1024), default="")
    artifacts: Mapped[Any] = mapped_column(JSON, default=list)
    command: Mapped[str] = mapped_column(Text, default="")

    evidence: Mapped[Evidence] = relationship(back_populates="jobs")
    batch: Mapped[Optional[Batch]] = relationship(back_populates="jobs")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="job", cascade="all, delete-orphan")

    @property
    def is_terminal(self) -> bool:
        return self.status in ("success", "failed", "cancelled", "empty")

    @property
    def duration_human(self) -> str:
        s = self.duration or 0
        if s < 60:
            return f"{s:.1f}s"
        m, s = divmod(int(s), 60)
        h, m = divmod(m, 60)
        return f"{h}h {m}m" if h else f"{m}m {s}s"


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Finding(Base):
    """An IOC / triage hit produced by the rules engine."""
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"), index=True)
    evidence_id: Mapped[int] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True)

    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(48), default="")
    title: Mapped[str] = mapped_column(String(300))
    detail: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    score: Mapped[int] = mapped_column(Integer, default=0)
    context: Mapped[Any] = mapped_column(JSON, default=dict)
    state: Mapped[str] = mapped_column(String(20), default="open")  # open|confirmed|dismissed
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    job: Mapped[Job] = relationship(back_populates="findings")

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 9)


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    evidence_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    case_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(300))
    fmt: Mapped[str] = mapped_column(String(16))       # html | pdf | json | csv | zip
    path: Mapped[str] = mapped_column(String(1024))
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Audit(Base):
    __tablename__ = "audit"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[str] = mapped_column(Text, default="")


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")

    @staticmethod
    def as_json(raw: str, fallback=None):
        try:
            return json.loads(raw)
        except Exception:
            return fallback
