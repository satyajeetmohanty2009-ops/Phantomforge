from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Run(Base):
    __tablename__ = "runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(512), index=True)
    scope: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), default="INIT")
    current_phase: Mapped[str] = mapped_column(String(32), default="INIT")
    config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    run_dir: Mapped[str] = mapped_column(String(1024))
    html_report: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    md_report: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    phases: Mapped[list["Phase"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="run", cascade="all, delete-orphan")
    cracked: Mapped[list["CrackedHash"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class Phase(Base):
    __tablename__ = "phases"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    name: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(32), default="PENDING")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    log: Mapped[str] = mapped_column(Text, default="")
    run: Mapped[Run] = relationship(back_populates="phases")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    phase: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(32), default="info")
    data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    run: Mapped[Run] = relationship(back_populates="findings")


class CrackedHash(Base):
    __tablename__ = "cracked_hashes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    source: Mapped[str] = mapped_column(String(64))
    hash_value: Mapped[str] = mapped_column(Text)
    password: Mapped[str] = mapped_column(String(512))
    format: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    run: Mapped[Run] = relationship(back_populates="cracked")


engine = None
SessionLocal: sessionmaker[Session] | None = None


def init_db(database_url: str) -> None:
    global engine, SessionLocal
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, connect_args=connect_args)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)


def get_session() -> Session:
    if SessionLocal is None:
        init_db("sqlite:///./phantomforge.db")
    assert SessionLocal is not None
    return SessionLocal()


def add_finding(db: Session, run_id: int, phase: str, kind: str, title: str, data: dict[str, Any], severity: str = "info") -> Finding:
    finding = Finding(run_id=run_id, phase=phase, kind=kind, title=title, data=data, severity=severity)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding
