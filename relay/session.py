"""Thread-safe lifecycle tracking for controlled relay simulations."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Iterable, Mapping
from uuid import uuid4


class RelaySessionError(Exception):
    """Base exception for relay-session failures."""


class InvalidSessionTransitionError(RelaySessionError):
    """Raised when a session is asked to enter an invalid state."""


class SessionNotFoundError(RelaySessionError):
    """Raised when a session ID is not managed by the session manager."""


class SessionState(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    CLEANED = "cleaned"


_FINDING_STATUSES = {"PASS", "FAIL", "UNKNOWN", "ERROR"}
_FINDING_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_FINDING_FIELDS = {
    "check_id",
    "title",
    "status",
    "severity",
    "details",
    "evidence",
    "remediation",
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _validated_targets(targets: Iterable[str]) -> tuple[str, ...]:
    if isinstance(targets, (str, bytes)):
        raise ValueError("targets must be an iterable of explicit target strings")

    normalized = tuple(targets)
    if not normalized:
        raise ValueError("at least one explicit target is required")
    if any(not isinstance(target, str) or not target.strip() for target in normalized):
        raise ValueError("each target must be a non-empty string")
    if any(target != target.strip() or any(char.isspace() for char in target) for target in normalized):
        raise ValueError("targets must not contain whitespace")
    if len(set(normalized)) != len(normalized):
        raise ValueError("duplicate targets are not allowed")
    return normalized


def _validate_finding(finding: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(finding, Mapping):
        raise TypeError("each session result must be a finding mapping")
    missing = _FINDING_FIELDS.difference(finding)
    if missing:
        raise ValueError(f"finding is missing required fields: {', '.join(sorted(missing))}")
    if not isinstance(finding["check_id"], str) or not finding["check_id"].strip():
        raise ValueError("finding check_id must be a non-empty string")
    if not isinstance(finding["title"], str) or not finding["title"].strip():
        raise ValueError("finding title must be a non-empty string")
    if finding["status"] not in _FINDING_STATUSES:
        raise ValueError("finding status must be PASS, FAIL, UNKNOWN, or ERROR")
    if finding["severity"] not in _FINDING_SEVERITIES:
        raise ValueError("finding severity must be INFO, LOW, MEDIUM, HIGH, or CRITICAL")
    if not isinstance(finding["details"], str):
        raise ValueError("finding details must be a string")
    if not isinstance(finding["evidence"], Mapping):
        raise ValueError("finding evidence must be a mapping")
    if not isinstance(finding["remediation"], str):
        raise ValueError("finding remediation must be a string")
    return deepcopy(dict(finding))


class RelaySession:
    """One simulation session with validated targets and immutable result snapshots."""

    def __init__(self, session_id: str, targets: Iterable[str]) -> None:
        if not session_id:
            raise ValueError("session_id must not be empty")
        self.session_id = session_id
        self.targets = _validated_targets(targets)
        self.created_at = _timestamp()
        self.started_at: str | None = None
        self.completed_at: str | None = None
        self.cleaned_at: str | None = None
        self.error_type: str | None = None
        self._state = SessionState.CREATED
        self._results: list[dict[str, Any]] = []
        self._lock = RLock()
        self.updated_at = self.created_at

    @property
    def state(self) -> SessionState:
        with self._lock:
            return self._state

    @property
    def results(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(self._results)

    def start(self) -> None:
        with self._lock:
            if self._state is not SessionState.CREATED:
                raise InvalidSessionTransitionError(
                    f"cannot start a session in state {self._state.value}"
                )
            self._state = SessionState.RUNNING
            self.started_at = self.updated_at = _timestamp()

    def complete(self, findings: Iterable[Mapping[str, Any]]) -> None:
        validated = [_validate_finding(finding) for finding in findings]
        with self._lock:
            if self._state is not SessionState.RUNNING:
                raise InvalidSessionTransitionError(
                    f"cannot complete a session in state {self._state.value}"
                )
            self._results = validated
            self._state = SessionState.COMPLETED
            self.completed_at = self.updated_at = _timestamp()

    def fail(self, error: BaseException) -> None:
        if not isinstance(error, BaseException):
            raise TypeError("error must be an exception")
        with self._lock:
            if self._state not in {SessionState.CREATED, SessionState.RUNNING}:
                raise InvalidSessionTransitionError(
                    f"cannot fail a session in state {self._state.value}"
                )
            self.error_type = type(error).__name__
            self._state = SessionState.FAILED
            self.completed_at = self.updated_at = _timestamp()

    def cancel(self) -> None:
        with self._lock:
            if self._state not in {SessionState.CREATED, SessionState.RUNNING}:
                raise InvalidSessionTransitionError(
                    f"cannot cancel a session in state {self._state.value}"
                )
            self._state = SessionState.CANCELLED
            self.completed_at = self.updated_at = _timestamp()

    def cleanup(self) -> None:
        with self._lock:
            if self._state is SessionState.CLEANED:
                return
            self._state = SessionState.CLEANED
            self.cleaned_at = self.updated_at = _timestamp()


class SessionManager:
    """Owns active sessions and ensures IDs are not reused after cleanup."""

    def __init__(self) -> None:
        self._sessions: dict[str, RelaySession] = {}
        self._issued_ids: set[str] = set()
        self._lock = RLock()

    def create_session(self, targets: Iterable[str]) -> RelaySession:
        validated_targets = _validated_targets(targets)
        with self._lock:
            session_id = str(uuid4())
            while session_id in self._issued_ids:
                session_id = str(uuid4())
            session = RelaySession(session_id, validated_targets)
            self._sessions[session_id] = session
            self._issued_ids.add(session_id)
            return session

    def get_session(self, session_id: str) -> RelaySession:
        with self._lock:
            try:
                return self._sessions[session_id]
            except KeyError as exc:
                raise SessionNotFoundError(f"session {session_id!r} was not found") from exc

    def cleanup_session(self, session_id: str) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.cleanup()
        return True

    def cleanup_all(self) -> int:
        with self._lock:
            sessions = tuple(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.cleanup()
        return len(sessions)

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)