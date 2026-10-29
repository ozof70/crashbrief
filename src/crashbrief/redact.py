"""Deterministic redaction. No secrets or reversible mappings leave this module."""
from collections import Counter
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern
    group: int = 0


RULES = (
    Rule("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\Z)")),
    Rule("url_credentials", re.compile(r"\b[a-z][a-z0-9+.-]{0,31}://([^\s/@]+)@", re.I), 1),
    Rule("authorization", re.compile(r"(?im)\b(?:authorization|proxy-authorization)\s*[:=]\s*[\"']?((?:Bearer|Basic)\s+[^\s\"',;]+)"), 1),
    Rule("cookie", re.compile(r"(?im)^\s*(?:set-cookie|cookie)\s*:\s*([^\r\n]+)"), 1),
    Rule("assignment", re.compile(
        r"(?i)(?<![\w-])[\"']?(?:[\w-]*[_-])?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|token|password|passwd|secret|client[_-]?secret|credential|authorization)[\"']?\s*[:=]\s*"
        r"(\"(?:\\.|[^\"\\\r\n])*(?:\"|(?=\r?$))|'(?:\\.|[^'\\\r\n])*(?:'|(?=\r?$))|[^\s,;&\"'}]+)", re.M), 1),
    Rule("known_token", re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{15,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,})\b")),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
    Rule("email", re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,254}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+\b")),
    Rule("home_path", re.compile(r"(?i)(?:[a-z]:[\\/]Users[\\/][^\\/\s\"'<>]+|/(?:Users|home)/[^/\s\"'<>]+)")),
)

ANSI = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]")
PLACEHOLDER = re.compile(r"\[REDACTED_\d+\]")


def normalize(text: str) -> str:
    text = ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return "".join(c for c in text if c in "\n\t" or (ord(c) >= 32 and c not in
        "\x7f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))


class Redactor:
    def __init__(self, literals: tuple[str, ...] = ()):
        if len(literals) > 100 or any(len(value) > 4096 for value in literals):
            raise ValueError("Use at most 100 custom literals of at most 4096 characters")
        self._values: dict[str, str] = {}
        self.counts: Counter[str] = Counter()
        self._literals = tuple(sorted(set(literals), key=len, reverse=True))

    def _replacement(self, value: str, category: str) -> str:
        if PLACEHOLDER.fullmatch(value.strip("\"'")):
            return value
        self.counts[category] += 1
        if value not in self._values:
            self._values[value] = f"[REDACTED_{len(self._values) + 1}]"
        return self._values[value]

    def redact(self, text: str) -> str:
        """Match original text, union overlapping spans, then replace once.

        Matching before substitution prevents rules from consuming placeholders
        inserted by another rule. Overlapping detections are merged so a short
        custom literal cannot leave the rest of a detected credential exposed.
        """
        text = normalize(text)
        spans: list[tuple[int, int, int, str]] = []
        for literal in self._literals:
            normalized = normalize(literal)
            if normalized:
                spans.extend((m.start(), m.end(), 0, "custom") for m in re.finditer(re.escape(normalized), text))
        for priority, rule in enumerate(RULES, 1):
            spans.extend((*m.span(rule.group), priority, rule.name) for m in rule.pattern.finditer(text))
        merged: list[tuple[int, int, int, str]] = []
        for start, end, priority, category in sorted(spans):
            if start == end:
                continue
            if merged and start < merged[-1][1]:
                left, right, previous_priority, previous_category = merged[-1]
                if previous_priority <= priority:
                    priority, category = previous_priority, previous_category
                merged[-1] = (left, max(right, end), priority, category)
            else:
                merged.append((start, end, priority, category))
        pieces, cursor = [], 0
        for start, end, _, category in merged:
            pieces.extend((text[cursor:start], self._replacement(text[start:end], category)))
            cursor = end
        pieces.append(text[cursor:])
        return "".join(pieces)
