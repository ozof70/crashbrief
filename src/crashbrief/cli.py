"""Read only explicit input. Never collect environment variables or run commands."""
import argparse
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import sys

from .report import build_report, render
from .compare import compare_reports
from .config import parse_config
from .redact import RULES

MAX_BYTES = 2 * 1024 * 1024


def read_file(path: str, limit: int) -> bytes:
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input file exceeds its size limit")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Turn error logs into redacted debugging reports. Offline.")
    parser.add_argument("inputs", nargs="*", help="Explicit UTF-8 log files, or - for stdin; default stdin")
    parser.add_argument("-o", "--output", help="New output file; existing files are never overwritten")
    parser.add_argument("--format", choices=("markdown", "html", "json"), default="markdown")
    parser.add_argument("--title", help="Report title (1–200 characters)")
    parser.add_argument("--redact-file", help="UTF-8 file of additional exact strings to redact, one per line")
    parser.add_argument("--config", help="Explicit TOML file containing title and redact strings")
    parser.add_argument("--compare", help="Compare with a previous CrashBrief JSON report")
    parser.add_argument("--rules", action="store_true", help="List built-in redaction rules without reading input")
    parser.add_argument("--fail-on-redaction", action="store_true", help="Write report, then exit 3 if patterns were redacted")
    parser.add_argument("--fail-on-error", action="store_true", help="Write report, then exit 4 if recognized error lines exist")
    parser.add_argument("--version", action="version", version="crashbrief 0.1.0")
    args = parser.parse_args(argv)
    if args.rules:
        print(json.dumps({"rules": [rule.name for rule in RULES], "custom_literals": True}, indent=2))
        return 0
    try:
        config = parse_config(read_file(args.config, 65536)) if args.config else parse_config(b"")
        title = args.title if args.title is not None else config.title
        if not 1 <= len(title) <= 200:
            raise ValueError("Title must contain 1–200 characters")
        inputs = args.inputs or ["-"]
        if len(inputs) > 20 or inputs.count("-") > 1:
            raise ValueError("Use at most 20 inputs and stdin at most once")
        if "-" in inputs and sys.stdin.isatty():
            raise ValueError("Provide a log filename or pipe UTF-8 input to stdin")
        chunks, total = [], 0
        for index, source in enumerate(inputs, 1):
            data = sys.stdin.buffer.read(MAX_BYTES-total+1) if source == "-" else read_file(source, MAX_BYTES-total)
            total += len(data)
            if total > MAX_BYTES:
                raise ValueError("Combined input exceeds the 2 MiB limit")
            label = f"----- input {index} -----\n" if len(inputs) > 1 else ""
            chunks.append(label + data.decode("utf-8-sig"))
        log = "\n".join(chunks)
        literals = config.literals
        if args.redact_file:
            custom = read_file(args.redact_file, 65536)
            literals += tuple(line for line in custom.decode("utf-8-sig").splitlines() if line)
        report = build_report(log, title, literals)
        if args.compare:
            try:
                baseline = json.loads(read_file(args.compare, 16 * 1024 * 1024).decode("utf-8-sig"))
            except json.JSONDecodeError as exc:
                raise ValueError("Baseline must be a valid CrashBrief JSON report") from exc
            report = replace(report, comparison=compare_reports(asdict(report), baseline, literals))
        result = render(report, args.format)
        if args.output:
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
                output.write(result)
        else:
            sys.stdout.write(result)
        if args.fail_on_redaction and report.redactions:
            return 3
        if args.fail_on_error and report.analysis["error_lines"]:
            return 4
        return 0
    except FileExistsError:
        print("crashbrief: output already exists; choose a new path", file=sys.stderr)
    except UnicodeError:
        print("crashbrief: input must be valid UTF-8", file=sys.stderr)
    except RecursionError:
        print("crashbrief: input structure is nested too deeply", file=sys.stderr)
    except ValueError as exc:
        # All ValueError messages originate in our validators, never raw input.
        print(f"crashbrief: {exc}", file=sys.stderr)
    except OSError:
        # Do not echo filenames or raw exceptions: they may contain sensitive input.
        print("crashbrief: could not read input or write output; check paths and permissions", file=sys.stderr)
    return 2
