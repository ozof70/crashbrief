"""Explicit TOML configuration, validated without evaluating code or regexes."""
from dataclasses import dataclass
import tomllib


@dataclass(frozen=True)
class Config:
    title: str = "Debugging report"
    literals: tuple[str, ...] = ()


def parse_config(data: bytes) -> Config:
    try:
        values = tomllib.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Configuration must be valid UTF-8 TOML") from exc
    if set(values) - {"title", "redact"}:
        raise ValueError("Unknown configuration field; allowed: title, redact")
    title = values.get("title", "Debugging report")
    literals = values.get("redact", [])
    if not isinstance(title, str) or not 1 <= len(title) <= 200:
        raise ValueError("Configuration title must contain 1–200 characters")
    if not isinstance(literals, list) or not all(isinstance(v, str) and v for v in literals):
        raise ValueError("Configuration redact must be a list of nonempty strings")
    if len(literals) > 100 or any(len(v) > 4096 for v in literals):
        raise ValueError("Use at most 100 custom literals of at most 4096 characters")
    return Config(title, tuple(literals))
