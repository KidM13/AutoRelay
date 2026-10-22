"""
AutoRelay — structured logging.

Two log sinks:
  - console: human-readable, colored if enabled
  - file:    one line per event, ISO-8601 timestamp + level + name + msg

Log files are written to <log_dir>/autorelay-YYYYMMDD-HHMMSS.log so each
run gets its own file. Nothing is overwritten.
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path

# Module-level singleton for the configured logger.
# Call setup() once at program start; call get_logger(__name__) everywhere else.
_LOGGER_NAME = "autorelay"
_configured = False


# ---------------------------------------------------------------------------
# ANSI colors (small palette, no dependency)
# ---------------------------------------------------------------------------

class _Color:
    RESET = "\033[0m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


_LEVEL_COLOR = {
    "DEBUG": _Color.DIM,
    "INFO": _Color.CYAN,
    "WARNING": _Color.YELLOW,
    "ERROR": _Color.RED,
    "CRITICAL": _Color.RED + "\033[1m",
}


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

class _ConsoleFormatter(logging.Formatter):
    def __init__(self, color: bool = True):
        super().__init__()
        self.color = color

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        level = record.levelname
        name = record.name.replace("autorelay.", "")

        if self.color:
            c = _LEVEL_COLOR.get(level, "")
            level_str = f"{c}{level:<8}{_Color.RESET}"
            name_str = f"{_Color.DIM}{name}{_Color.RESET}"
        else:
            level_str = f"{level:<8}"
            name_str = name

        msg = record.getMessage()
        line = f"{ts}  {level_str}  {name_str}  {msg}"

        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class _FileFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3]
        name = record.name
        level = record.levelname
        msg = record.getMessage()
        line = f"{ts}  {level:<8}  {name}  {msg}"
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def setup(
    log_dir: str | Path,
    level: str = "INFO",
    console: bool = True,
    file: bool = True,
    color: bool = True,
) -> Path | None:
    """
    Configure the autorelay logger. Safe to call once at startup.

    Returns the path to the log file if file logging was enabled, else None.
    """
    global _configured

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)  # handlers do the filtering
    logger.handlers.clear()
    logger.propagate = False

    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")

    log_path: Path | None = None

    if file:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        log_path = log_dir / f"autorelay-{ts}.log"

        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(numeric_level)
        fh.setFormatter(_FileFormatter())
        logger.addHandler(fh)

    if console:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(numeric_level)
        ch.setFormatter(_ConsoleFormatter(color=color))
        logger.addHandler(ch)

    _configured = True
    return log_path


def get_logger(name: str | None = None) -> logging.Logger:
    """
    Get a child logger. Use get_logger(__name__) in each module.

    If setup() has not been called, logging still works but only prints
    warnings and above to stderr, so imports don't crash.
    """
    if not _configured:
        # Fallback: minimal stderr handler so early imports don't break.
        logger = logging.getLogger(_LOGGER_NAME)
        if not logger.handlers:
            h = logging.StreamHandler(sys.stderr)
            h.setLevel(logging.WARNING)
            h.setFormatter(_ConsoleFormatter(color=False))
            logger.addHandler(h)

    if name and name.startswith("autorelay."):
        return logging.getLogger(name)
    if name:
        return logging.getLogger(f"{_LOGGER_NAME}.{name}")
    return logging.getLogger(_LOGGER_NAME)


# ---------------------------------------------------------------------------
# Self-test — run with: python -m util.log
# ---------------------------------------------------------------------------

def _main() -> int:
    log_path = setup(
        log_dir="logs/_selftest",
        level="DEBUG",
        console=True,
        file=True,
        color=True,
    )
    log = get_logger("util.log.selftest")

    log.debug("this is a debug message")
    log.info("this is an info message")
    log.warning("this is a warning")
    log.error("this is an error")

    try:
        raise RuntimeError("sample exception")
    except RuntimeError:
        log.exception("caught an exception")

    if log_path:
        print(f"\nlog file: {log_path}")
        print("--- file contents ---")
        print(log_path.read_text())
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
