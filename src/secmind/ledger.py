from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from secmind.schemas import AgentState, LedgerEvent, RunStatus

ZERO_HASH = "0" * 64
SECRET_KEYS = {"api_key", "apikey", "authorization", "password", "secret", "token"}
SECRET_PATTERN = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "ledger_events"
    __table_args__ = (UniqueConstraint("run_id", "sequence"),)

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(36), index=True)
    sequence: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    actor: Mapped[str] = mapped_column(String(100))
    payload_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class RunRow(Base):
    __tablename__ = "runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    status: Mapped[str] = mapped_column(String(30), index=True)
    state_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class QueryLogRow(Base):
    """Query history log — records every knowledge retrieval query along with its results."""

    __tablename__ = "query_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str | None] = mapped_column(String(36), index=True, nullable=True)
    query_text: Mapped[str] = mapped_column(Text)
    query_vector_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    top_k: Mapped[int] = mapped_column(Integer, default=5)
    hits_json: Mapped[str] = mapped_column(Text)
    hit_count: Mapped[int] = mapped_column(Integer, default=0)
    embedding_model: Mapped[str] = mapped_column(String(100), default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)


def redact(value: Any) -> Any:
    """Redact common secret fields before they enter durable logs."""
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key.lower() in SECRET_KEYS else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return SECRET_PATTERN.sub(r"\1[REDACTED]", value)
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


class LedgerStore:
    """Append-only hash-chained event store plus persisted run snapshots."""

    def __init__(self, database_url: str) -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, future=True, connect_args=connect_args)
        self._locks: dict[str, threading.RLock] = {}
        self._locks_guard = threading.Lock()
        Base.metadata.create_all(self.engine)

    def _lock_for(self, run_id: str) -> threading.RLock:
        with self._locks_guard:
            return self._locks.setdefault(run_id, threading.RLock())

    def append(self, run_id: str, event_type: str, payload: dict[str, Any], actor: str = "system") -> LedgerEvent:
        safe_payload = redact(payload)
        with self._lock_for(run_id), Session(self.engine) as session:
            previous = session.scalars(
                select(EventRow).where(EventRow.run_id == run_id).order_by(EventRow.sequence.desc()).limit(1)
            ).first()
            sequence = 1 if previous is None else previous.sequence + 1
            prev_hash = ZERO_HASH if previous is None else previous.hash
            timestamp = datetime.now(UTC)
            event_id = str(uuid4())
            digest_input = {
                "event_id": event_id,
                "run_id": run_id,
                "sequence": sequence,
                "event_type": event_type,
                "timestamp": timestamp.isoformat(),
                "actor": actor,
                "payload": safe_payload,
                "prev_hash": prev_hash,
            }
            digest = hashlib.sha256(canonical_json(digest_input).encode()).hexdigest()
            row = EventRow(
                event_id=event_id,
                run_id=run_id,
                sequence=sequence,
                event_type=event_type,
                timestamp=timestamp,
                actor=actor,
                payload_json=canonical_json(safe_payload),
                prev_hash=prev_hash,
                hash=digest,
            )
            session.add(row)
            session.commit()
            return self._to_event(row)

    def events(self, run_id: str, after_sequence: int = 0, limit: int = 1000) -> list[LedgerEvent]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(EventRow)
                .where(EventRow.run_id == run_id, EventRow.sequence > after_sequence)
                .order_by(EventRow.sequence)
                .limit(limit)
            ).all()
            return [self._to_event(row) for row in rows]

    def verify(self, run_id: str) -> bool:
        previous = ZERO_HASH
        for event in self.events(run_id, limit=1_000_000):
            if event.prev_hash != previous:
                return False
            digest_input = {
                "event_id": event.event_id,
                "run_id": event.run_id,
                "sequence": event.sequence,
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "actor": event.actor,
                "payload": event.payload,
                "prev_hash": event.prev_hash,
            }
            expected = hashlib.sha256(canonical_json(digest_input).encode()).hexdigest()
            if expected != event.hash:
                return False
            previous = event.hash
        return True

    def save_state(self, state: AgentState) -> None:
        now = datetime.now(UTC)
        state_json = state.model_dump_json()
        with self._lock_for(state.run_id), Session(self.engine) as session:
            row = session.get(RunRow, state.run_id)
            if row is None:
                row = RunRow(
                    run_id=state.run_id,
                    status=state.status.value,
                    state_json=state_json,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.status = state.status.value
                row.state_json = state_json
                row.updated_at = now
            session.commit()

    def load_state(self, run_id: str) -> AgentState | None:
        with Session(self.engine) as session:
            row = session.get(RunRow, run_id)
            return None if row is None else AgentState.model_validate_json(row.state_json)

    def incomplete_run_ids(self) -> list[str]:
        terminal = {
            RunStatus.COMPLETED.value,
            RunStatus.PARTIAL.value,
            RunStatus.DENIED.value,
            RunStatus.FAILED.value,
        }
        with Session(self.engine) as session:
            return list(session.scalars(select(RunRow.run_id).where(RunRow.status.not_in(terminal))).all())

    def export_jsonl(self, run_id: str, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as output:
            for event in self.events(run_id, limit=1_000_000):
                output.write(event.model_dump_json() + "\n")
        return destination

    # ----------------------------------------------------------------
    # Query logging
    # ----------------------------------------------------------------

    def log_query(
        self,
        query_text: str,
        hits_json: str,
        hit_count: int,
        *,
        run_id: str | None = None,
        query_vector_json: str | None = None,
        top_k: int = 5,
        embedding_model: str = "",
        duration_ms: int | None = None,
    ) -> int:
        """Record a knowledge retrieval query and its results in the query log."""
        with Session(self.engine) as session:
            row = QueryLogRow(
                run_id=run_id,
                query_text=query_text,
                query_vector_json=query_vector_json,
                top_k=top_k,
                hits_json=hits_json,
                hit_count=hit_count,
                embedding_model=embedding_model,
                timestamp=datetime.now(UTC),
                duration_ms=duration_ms,
            )
            session.add(row)
            session.commit()
            return row.id

    def query_logs(
        self,
        limit: int = 100,
        run_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return recent query logs, optionally filtered by run_id."""
        with Session(self.engine) as session:
            q = select(QueryLogRow).order_by(QueryLogRow.timestamp.desc())
            if run_id is not None:
                q = q.where(QueryLogRow.run_id == run_id)
            rows = session.scalars(q.limit(limit)).all()
            return [
                {
                    "id": r.id,
                    "run_id": r.run_id,
                    "query_text": r.query_text,
                    "hit_count": r.hit_count,
                    "hits": json.loads(r.hits_json),
                    "embedding_model": r.embedding_model,
                    "timestamp": r.timestamp.isoformat(),
                    "duration_ms": r.duration_ms,
                }
                for r in rows
            ]

    @staticmethod
    def _to_event(row: EventRow) -> LedgerEvent:
        return LedgerEvent(
            event_id=row.event_id,
            run_id=row.run_id,
            sequence=row.sequence,
            event_type=row.event_type,
            timestamp=row.timestamp.replace(tzinfo=row.timestamp.tzinfo or UTC),
            actor=row.actor,
            payload=json.loads(row.payload_json),
            prev_hash=row.prev_hash,
            hash=row.hash,
        )
