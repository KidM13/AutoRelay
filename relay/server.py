"""In-process relay-session simulation service.

This module deliberately performs no network relay, authentication handling,
or credential processing. It only exercises the configured session lifecycle.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from threading import Event, RLock, Thread
from typing import Any, Sequence

from .session import RelaySession, SessionManager, _validated_targets


class RelayError(Exception):
    """Base exception for relay service failures."""


class RelayConfigurationError(RelayError, ValueError):
    """Raised when relay simulation configuration is invalid."""


class RelayLifecycleError(RelayError):
    """Raised when the relay simulation service cannot change lifecycle state."""


class RelayTimeoutError(RelayLifecycleError, TimeoutError):
    """Raised when startup or shutdown exceeds its configured timeout."""


class ServerState(str, Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    READY = "ready"
    STOPPING = "stopping"
    FAILED = "failed"


def _validate_timeout(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RelayConfigurationError(f"{name} must be a positive finite number")
    try:
        is_valid = math.isfinite(value) and value > 0
    except OverflowError:
        is_valid = False
    if not is_valid:
        raise RelayConfigurationError(f"{name} must be a positive finite number")


@dataclass(frozen=True)
class RelayConfig:
    """Validated, explicit configuration for a simulation-only relay service."""

    relay_targets: Sequence[str]
    startup_timeout: float = 5.0
    shutdown_timeout: float = 5.0

    def __post_init__(self) -> None:
        try:
            targets = _validated_targets(self.relay_targets)
        except (TypeError, ValueError) as exc:
            raise RelayConfigurationError(str(exc)) from exc
        object.__setattr__(self, "relay_targets", targets)
        for name, value in (
            ("startup_timeout", self.startup_timeout),
            ("shutdown_timeout", self.shutdown_timeout),
        ):
            _validate_timeout(name, value)

    def validate(self) -> None:
        """Recheck configuration at service startup."""
        try:
            _validated_targets(self.relay_targets)
        except (TypeError, ValueError) as exc:
            raise RelayConfigurationError(str(exc)) from exc
        for name, value in (
            ("startup_timeout", self.startup_timeout),
            ("shutdown_timeout", self.shutdown_timeout),
        ):
            _validate_timeout(name, value)


class RelayServer:
    """Manages the in-process relay simulation service and its sessions."""

    def __init__(
        self,
        config: RelayConfig,
        session_manager: SessionManager | None = None,
    ) -> None:
        self.config = config
        self.sessions = session_manager if session_manager is not None else SessionManager()
        self._state = ServerState.STOPPED
        self._lock = RLock()
        self._ready_event = Event()
        self._stop_event = Event()
        self._thread: Thread | None = None

    @property
    def state(self) -> ServerState:
        with self._lock:
            return self._state

    def start(self) -> "RelayServer":
        self.config.validate()
        with self._lock:
            if self._state is ServerState.READY:
                return self
            if self._state is not ServerState.STOPPED:
                raise RelayLifecycleError(
                    f"cannot start relay service in state {self._state.value}"
                )
            self._state = ServerState.STARTING
            self._ready_event.clear()
            self._stop_event.clear()
            self._thread = Thread(
                target=self._serve,
                name="autorelay-simulation",
                daemon=True,
            )
            thread = self._thread
            try:
                thread.start()
            except RuntimeError as exc:
                self._state = ServerState.FAILED
                self._thread = None
                self.sessions.cleanup_all()
                raise RelayLifecycleError("relay simulation service could not start") from exc

        if not self._ready_event.wait(self.config.startup_timeout):
            self._stop_event.set()
            thread.join(self.config.shutdown_timeout)
            with self._lock:
                self._state = ServerState.FAILED
            self.sessions.cleanup_all()
            if thread.is_alive():
                raise RelayTimeoutError(
                    "relay simulation startup timed out and its worker did not stop"
                )
            raise RelayTimeoutError("relay simulation startup timed out")

        with self._lock:
            if self._state is not ServerState.READY:
                raise RelayLifecycleError("relay simulation service failed during startup")
        return self

    def _serve(self) -> None:
        with self._lock:
            if self._state is not ServerState.STARTING:
                self._ready_event.set()
                return
            self._state = ServerState.READY
            self._ready_event.set()
        self._stop_event.wait()
        with self._lock:
            if self._state is ServerState.STOPPING:
                self._state = ServerState.STOPPED

    def is_ready(self) -> bool:
        with self._lock:
            return (
                self._state is ServerState.READY
                and self._thread is not None
                and self._thread.is_alive()
            )

    def status(self) -> dict[str, Any]:
        with self._lock:
            state = self._state
            thread = self._thread
        return {
            "state": state.value,
            "ready": self.is_ready(),
            "configured_target_count": len(self.config.relay_targets),
            "active_session_count": len(self.sessions),
            "worker_alive": thread is not None and thread.is_alive(),
            "mode": "simulation",
        }

    def simulate_session(self) -> RelaySession:
        with self._lock:
            if not self.is_ready():
                raise RelayLifecycleError("relay simulation service is not ready")
            session = self.sessions.create_session(self.config.relay_targets)
            session.start()
            try:
                session.complete(
                    [
                        {
                            "check_id": "relay.simulation.lifecycle",
                            "title": "Relay session lifecycle simulation",
                            "status": "PASS",
                            "severity": "INFO",
                            "details": (
                                "The in-process session lifecycle completed; no network "
                                "connections or authentication data were used."
                            ),
                            "evidence": {
                                "mode": "simulation",
                                "configured_target_count": len(session.targets),
                            },
                            "remediation": "No remediation is required for this simulation.",
                        }
                    ]
                )
            except (TypeError, ValueError) as exc:
                session.fail(exc)
                raise RelayLifecycleError(
                    "relay simulation session could not be completed"
                ) from exc
            return session

    def stop(self) -> None:
        with self._lock:
            if self._state is ServerState.STOPPED:
                self.sessions.cleanup_all()
                return
            if self._state is not ServerState.FAILED:
                self._state = ServerState.STOPPING
            self._stop_event.set()
            thread = self._thread

        if thread is not None:
            thread.join(self.config.shutdown_timeout)
            if thread.is_alive():
                with self._lock:
                    self._state = ServerState.FAILED
                self.sessions.cleanup_all()
                raise RelayTimeoutError("relay simulation shutdown timed out")

        with self._lock:
            if self._state is not ServerState.FAILED:
                self._state = ServerState.STOPPED
        self.sessions.cleanup_all()