"""
AutoRelay — configuration loader and scope enforcement.

Loads a profile from config.yaml and (in live mode) enforces a scope
file before any offensive action is permitted.

This module has no side effects on import. It does not touch the network.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Raised when configuration is missing, malformed, or inconsistent."""


class ScopeViolation(Exception):
    """Raised when an action would violate the engagement scope."""


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Capabilities:
    preflight: bool
    coercion: bool
    relay: bool
    post_exploitation: bool


@dataclass
class Safety:
    require_confirmation: bool
    allow_yes_flag: bool
    hard_scope_enforcement: bool
    require_scope_file: bool


@dataclass
class Timeouts:
    tcp_connect: int
    smb_negotiate: int
    ldap_bind: int
    rpc_bind: int
    relay_session_wait: int
    coercion_retry_interval: int


@dataclass
class Logging:
    level: str
    log_dir: str
    console: bool
    file: bool


@dataclass
class Output:
    report_dir: str
    color: bool


@dataclass
class Profile:
    name: str
    description: str
    mode: str                         # "lab" | "production"
    capabilities: Capabilities
    safety: Safety
    timeouts: Timeouts
    logging: Logging
    output: Output

    # Set when a scope file is loaded (live mode only)
    scope: Scope | None = None

    @property
    def is_live(self) -> bool:
        return self.mode == "production"

    @property
    def is_lab(self) -> bool:
        return self.mode == "lab"


# ---------------------------------------------------------------------------
# Scope file
# ---------------------------------------------------------------------------

@dataclass
class ScopeEngagement:
    client: str
    authorized_by: str
    authorization_ref: str
    start_date: str
    end_date: str


@dataclass
class ScopeTargets:
    coercion: list[str] = field(default_factory=list)
    relay: list[str] = field(default_factory=list)


@dataclass
class ScopeConstraints:
    no_persistence: bool = True
    no_data_exfil: bool = True
    no_dos: bool = True
    working_hours_only: bool = False
    working_hours: str = ""


@dataclass
class Scope:
    engagement: ScopeEngagement
    targets: ScopeTargets
    excluded: list[str] = field(default_factory=list)
    constraints: ScopeConstraints = field(default_factory=ScopeConstraints)

    def allows_coercion(self, host: str) -> bool:
        return host in self.targets.coercion

    def allows_relay(self, host: str) -> bool:
        return host in self.targets.relay

    def is_excluded(self, host: str) -> bool:
        # Exact match against excluded entries. CIDR support comes in a
        # later stage; for now this catches the obvious cases.
        return host in self.excluded


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

# Path to config.yaml — resolved relative to this file, so the tool works
# regardless of the current working directory.
CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


def _require(d: dict, key: str, ctx: str) -> Any:
    if key not in d:
        raise ConfigError(f"Missing required key '{key}' in {ctx}")
    return d[key]


def load_config(path: Path = CONFIG_PATH) -> dict:
    """Load and parse config.yaml. Returns the raw dict."""
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse {path}: {e}") from e
    if not isinstance(data, dict):
        raise ConfigError(f"Config file {path} did not parse to a mapping")
    return data


def load_profile(name: str, config: dict | None = None) -> Profile:
    """Load a named profile from config.yaml."""
    if config is None:
        config = load_config()

    profiles = config.get("profiles", {})
    if name not in profiles:
        available = ", ".join(profiles.keys()) or "(none)"
        raise ConfigError(
            f"Profile '{name}' not found. Available: {available}"
        )

    p = profiles[name]

    try:
        capabilities = Capabilities(**_require(p, "capabilities", name))
        safety = Safety(**_require(p, "safety", name))
        timeouts = Timeouts(**_require(p, "timeouts", name))
        logging_cfg = Logging(**_require(p, "logging", name))
        output = Output(**_require(p, "output", name))
    except TypeError as e:
        raise ConfigError(
            f"Profile '{name}' has missing or extra fields: {e}"
        ) from e

    return Profile(
        name=name,
        description=p.get("description", ""),
        mode=_require(p, "mode", name),
        capabilities=capabilities,
        safety=safety,
        timeouts=timeouts,
        logging=logging_cfg,
        output=output,
    )


def load_scope(path: Path) -> Scope:
    """Load a scope file. Used only in live mode."""
    if not path.exists():
        raise ConfigError(f"Scope file not found: {path}")
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse scope file {path}: {e}") from e

    try:
        engagement = ScopeEngagement(**_require(data, "engagement", str(path)))
        targets = ScopeTargets(**_require(data, "targets", str(path)))
        excluded = data.get("excluded", [])
        constraints_raw = data.get("constraints", {})
        constraints = ScopeConstraints(**constraints_raw)
    except TypeError as e:
        raise ConfigError(f"Scope file {path} has invalid fields: {e}") from e

    return Scope(
        engagement=engagement,
        targets=targets,
        excluded=excluded,
        constraints=constraints,
    )


# ---------------------------------------------------------------------------
# Scope enforcement
# ---------------------------------------------------------------------------

def enforce_scope(profile: Profile, host: str, action: str) -> None:
    """
    Raise ScopeViolation if `action` against `host` is not authorized.

    In lab mode (profile.safety.hard_scope_enforcement is False), this is
    a no-op — the operator is responsible for their own lab.

    In live mode, this is the wall: any action not explicitly authorized
    in the scope file raises, and the caller must handle it.

    action: "coercion" | "relay" | "preflight" | "post_exploitation"
    """
    if not profile.safety.hard_scope_enforcement:
        return

    if profile.scope is None:
        raise ScopeViolation(
            f"Scope enforcement is on but no scope file is loaded "
            f"(action={action}, host={host})"
        )

    if profile.scope.is_excluded(host):
        raise ScopeViolation(
            f"Host {host} matches an exclusion in the scope file"
        )

    if action == "coercion":
        if not profile.scope.allows_coercion(host):
            raise ScopeViolation(
                f"Host {host} is not authorized for coercion"
            )
    elif action == "relay":
        if not profile.scope.allows_relay(host):
            raise ScopeViolation(
                f"Host {host} is not authorized as a relay target"
            )
    elif action == "post_exploitation":
        # Post-exploitation follows relay authorization
        if not profile.scope.allows_relay(host):
            raise ScopeViolation(
                f"Host {host} is not authorized for post-exploitation"
            )
    elif action == "preflight":
        # Preflight is read-only; allow it against anything in scope,
        # and in live mode we still require the host to be listed
        # somewhere in the scope file.
        if not (
            profile.scope.allows_coercion(host)
            or profile.scope.allows_relay(host)
        ):
            raise ScopeViolation(
                f"Host {host} is not listed in the scope file"
            )
    else:
        raise ScopeViolation(f"Unknown action '{action}'")


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------

def build_profile_from_args(args: argparse.Namespace) -> Profile:
    """
    Given parsed CLI args (expecting .profile and optionally .scope),
    load the profile and scope, and validate the combination.

    Rules:
      - live profile requires a scope file
      - --yes is rejected in live mode
      - lab profile ignores any supplied scope file with a warning
    """
    config = load_config()
    default = config.get("default_profile", "goad")
    profile_name = getattr(args, "profile", None) or default

    profile = load_profile(profile_name, config)

    scope_arg = getattr(args, "scope", None)

    if profile.safety.require_scope_file:
        if not scope_arg:
            raise ConfigError(
                f"Profile '{profile.name}' requires --scope <file>"
            )
        profile.scope = load_scope(Path(scope_arg))
    elif scope_arg:
        print(
            f"warning: --scope provided but profile '{profile.name}' "
            f"does not use scope files; ignoring",
            file=sys.stderr,
        )

    yes_flag = getattr(args, "yes", False)
    if yes_flag and not profile.safety.allow_yes_flag:
        raise ConfigError(
            f"--yes is not permitted in profile '{profile.name}'"
        )

    return profile


# ---------------------------------------------------------------------------
# Self-test — run with: python config.py --profile goad
# ---------------------------------------------------------------------------

def _main() -> int:
    parser = argparse.ArgumentParser(
        description="AutoRelay config loader — self-test"
    )
    parser.add_argument("--profile", default=None)
    parser.add_argument("--scope", default=None)
    args = parser.parse_args()

    try:
        profile = build_profile_from_args(args)
    except (ConfigError, ScopeViolation) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"Profile:      {profile.name}")
    print(f"Description:  {profile.description}")
    print(f"Mode:         {profile.mode}")
    print(f"Capabilities: "
          f"preflight={profile.capabilities.preflight} "
          f"coercion={profile.capabilities.coercion} "
          f"relay={profile.capabilities.relay} "
          f"post={profile.capabilities.post_exploitation}")
    print(f"Safety:       "
          f"confirm={profile.safety.require_confirmation} "
          f"allow_yes={profile.safety.allow_yes_flag} "
          f"scope_enforced={profile.safety.hard_scope_enforcement}")
    print(f"Timeouts:     tcp={profile.timeouts.tcp_connect}s "
          f"smb={profile.timeouts.smb_negotiate}s "
          f"ldap={profile.timeouts.ldap_bind}s "
          f"rpc={profile.timeouts.rpc_bind}s")
    print(f"Logging:      level={profile.logging.level} "
          f"dir={profile.logging.log_dir}")
    if profile.scope:
        print(f"Scope:        client={profile.scope.engagement.client} "
              f"ref={profile.scope.engagement.authorization_ref}")
        print(f"              coercion targets={profile.scope.targets.coercion}")
        print(f"              relay targets={profile.scope.targets.relay}")

    return 0


if __name__ == "__main__":
    sys.exit(_main())
