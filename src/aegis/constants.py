"""Deterministic constants for Aegis Phase 1."""

ALLOWED_COMMANDS: frozenset[str] = frozenset({"move", "stop", "inspect", "wait"})

MIN_PRIORITY = 1
MAX_PRIORITY = 10

MAX_PARAMETER_DEPTH = 16
MAX_PARAMETER_KEYS = 128
MAX_STRING_LENGTH = 10_000

MAX_WAIT_DURATION_MS = 60_000
