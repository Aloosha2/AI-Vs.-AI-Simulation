"""Security controls and structured logging for the toy communication API.

The defaults intentionally leave common controls disabled so the class demo can
show what changes when a blue-team agent enables defenses. All state is local
and in-memory except for the JSON-lines security log.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any


DEFAULT_LOG_PATH = Path(os.environ.get("CYBER_SIM_LOG", "logs/security.log"))


@dataclass
class DefenseConfig:
    rate_limit_enabled: bool = False
    account_lockout_enabled: bool = False
    payload_validation_enabled: bool = False
    safer_errors_enabled: bool = False
    max_requests_per_window: int = 8
    window_seconds: int = 60
    max_failed_logins: int = 3
    max_message_chars: int = 500


@dataclass
class SecurityState:
    request_history: dict[str, list[float]]
    failed_logins: dict[str, int]
    locked_users: set[str]


config = DefenseConfig()
state = SecurityState(request_history={}, failed_logins={}, locked_users=set())
log_path = DEFAULT_LOG_PATH


def configure_log_file(path: str | Path) -> None:
    """Set the local JSON-lines log path used by the server and agents."""

    global log_path
    log_path = Path(path)
    log_path.parent.mkdir(parents=True, exist_ok=True)


def reset_security_state(clear_log: bool = False) -> None:
    """Reset mutable simulation state between tests or judge rounds."""

    global config, state
    config = DefenseConfig()
    state = SecurityState(request_history={}, failed_logins={}, locked_users=set())
    if clear_log and log_path.exists():
        log_path.unlink()


def apply_defense_profile(profile: str = "standard") -> DefenseConfig:
    """Enable a named defensive profile.

    The project keeps one practical profile for clarity, but a string argument
    makes it easy for students to extend the simulation with new strategies.
    """

    if profile != "standard":
        raise ValueError(f"unknown defense profile: {profile}")

    config.rate_limit_enabled = True
    config.account_lockout_enabled = True
    config.payload_validation_enabled = True
    config.safer_errors_enabled = True
    return config


def log_event(event_type: str, **details: Any) -> None:
    """Append a structured security event to the local log file."""

    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "details": details,
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def read_events(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Read structured log events, skipping malformed lines."""

    source = Path(path) if path is not None else log_path
    if not source.exists():
        return []

    events: list[dict[str, Any]] = []
    with source.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def check_rate_limit(client_id: str, endpoint: str, now: float) -> bool:
    """Return True when the current request should be blocked."""

    if not config.rate_limit_enabled:
        return False

    key = f"{client_id}:{endpoint}"
    window_start = now - config.window_seconds
    recent = [stamp for stamp in state.request_history.get(key, []) if stamp >= window_start]
    recent.append(now)
    state.request_history[key] = recent

    if len(recent) > config.max_requests_per_window:
        log_event(
            "rate_limit_block",
            client_id=client_id,
            endpoint=endpoint,
            requests=len(recent),
        )
        return True
    return False


def record_failed_login(username: str, client_id: str) -> None:
    """Track failed logins and lock an account when that defense is enabled."""

    state.failed_logins[username] = state.failed_logins.get(username, 0) + 1
    log_event(
        "failed_login",
        username=username,
        client_id=client_id,
        failures=state.failed_logins[username],
    )
    if (
        config.account_lockout_enabled
        and state.failed_logins[username] >= config.max_failed_logins
    ):
        state.locked_users.add(username)
        log_event("account_locked", username=username, client_id=client_id)


def clear_failed_logins(username: str) -> None:
    state.failed_logins.pop(username, None)


def is_locked(username: str) -> bool:
    return username in state.locked_users


def validate_message_content(content: str) -> tuple[bool, str]:
    """Validate a message only when payload defenses are enabled."""

    if not config.payload_validation_enabled:
        return True, ""
    if not isinstance(content, str) or not content.strip():
        return False, "Message content must be non-empty text."
    if len(content) > config.max_message_chars:
        return False, f"Message content exceeds {config.max_message_chars} characters."
    return True, ""


def public_error(verbose_message: str, safe_message: str) -> str:
    """Choose intentionally verbose or safer API errors based on defenses."""

    return safe_message if config.safer_errors_enabled else verbose_message


def config_snapshot() -> dict[str, Any]:
    return asdict(config)
