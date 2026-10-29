"""Explain observable signatures without pretending to infer a root cause."""
from collections import Counter
import re

SIGNATURES = (
    ("connection_refused", r"ECONNREFUSED|ConnectionRefusedError|connection refused",
     "Connection refused", "Check that the target service is running and listening on the configured host and port. Check container port mappings."),
    ("missing_dependency", r"ModuleNotFoundError|Cannot find module|ERR_MODULE_NOT_FOUND|ImportError",
     "Dependency or import failure", "Verify the active environment, dependency installation, import path, and package name."),
    ("permission_denied", r"PermissionError|EACCES|permission denied",
     "Permission denied", "Check the process identity and ownership of the affected resource before changing permissions."),
    ("timeout", r"TimeoutError|ETIMEDOUT|timed? out|deadline exceeded",
     "Operation timed out", "Check target availability, latency, and timeout settings. Confirm whether the receiver completed the operation before retrying."),
    ("out_of_memory", r"MemoryError|JavaScript heap out of memory|out of memory|OOMKilled",
     "Memory exhaustion", "Check process or container memory limits and whether payload size or concurrency increased."),
    ("disk_full", r"ENOSPC|No space left on device",
     "Storage exhausted", "Check free disk space, inode usage, and log growth before removing any files."),
    ("dns_failure", r"ENOTFOUND|EAI_AGAIN|Name or service not known|getaddrinfo failed",
     "Name resolution failure", "Verify the hostname and DNS configuration from the same runtime or container."),
)
ERROR_LINE = re.compile(r"\b(?:[A-Za-z_][\w.]*Error|Exception|ERROR|FATAL|ECONNREFUSED|EACCES|ENOSPC|ETIMEDOUT|ENOTFOUND)\b", re.I)
TIMESTAMP = re.compile(r"^\[?\d{4}-\d{2}-\d{2}[T ][0-9:.]+(?:Z|[+-]\d{2}:?\d{2})?\]?\s*")
PYTHON_FRAME = re.compile(r'File "([^"\n]+)", line (\d{1,9})(?!\d)(?:, in ([^\n]+))?')
JS_FRAME = re.compile(r"^\s*at\s+(.+?):(\d{1,9}):(\d{1,9})\)?\s*$")


def analyze(text: str) -> dict:
    lines = text.splitlines()
    errors = [line.strip() for line in lines if ERROR_LINE.search(line)]
    counts = Counter(TIMESTAMP.sub("", line) for line in errors)
    frames = []
    for number, line in enumerate(lines, 1):
        if len(frames) == 20:
            break
        match = PYTHON_FRAME.search(line)
        if match:
            frames.append({"language": "python", "location": match[1], "line": int(match[2]),
                           "function": match[3] or "", "log_line": number})
        elif match := JS_FRAME.match(line):
            frames.append({"language": "javascript", "location": match[1], "line": int(match[2]),
                           "column": int(match[3]), "log_line": number})
    signals = []
    for code, pattern, title, action in SIGNATURES:
        matches = [i for i, line in enumerate(lines, 1) if re.search(pattern, line, re.I)]
        if matches:
            signals.append({"code": code, "title": title, "lines": matches, "next_step": action})
    return {
        "line_count": len(lines), "error_lines": len(errors),
        "unique_error_lines": len(counts),
        "top_errors": [{"text": text, "count": count} for text, count in counts.most_common(5)],
        "signals": signals,
        "stack_frames": frames,
    }
