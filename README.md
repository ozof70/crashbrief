# CrashBrief

**Your logs are noisy. Your bug report doesn't have to be.**

[![Tests](https://github.com/ozof70/crashbrief/actions/workflows/tests.yml/badge.svg)](https://github.com/ozof70/crashbrief/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB)
![Dependencies](https://img.shields.io/badge/runtime_dependencies-0-22c55e)
![Offline](https://img.shields.io/badge/processing-local_only-22c55e)

Turn error logs into a redacted debugging brief for a teammate, a GitHub issue, or an AI assistant. Get error summaries, evidence line numbers, stack frames, suggested checks, and a report you can review before sharing.

**No API key. No uploads. No AI subscription. Python standard library at runtime.**

```sh
crashbrief app.log --title "Checkout worker failure" -o report.md
```

## See the result

| Input | Reviewed output |
| --- | --- |
| `API_KEY="demo-secret"` | `API_KEY=[REDACTED_1]` |
| `Authorization: Bearer demo-token` | `Authorization: [REDACTED_2]` |
| `ConnectionRefusedError` repeated with timestamps | One grouped error, occurrence count, evidence lines, next checks |
| `/home/developer/app/worker.py` | `[REDACTED_3]/app/worker.py` |

Explore the generated [Markdown report](examples/report.md), [JSON report](examples/report.json), and [standalone HTML report](examples/report.html) from [the synthetic demo log](examples/demo.log). Download the HTML file and open it locally; it needs no server, scripts, fonts, or external assets.

## Install from this repository

Python 3.11 or newer is required.

```sh
python -m pip install "git+https://github.com/ozof70/crashbrief.git"
crashbrief --version
```

Or clone and install locally:

```sh
git clone https://github.com/ozof70/crashbrief.git
cd crashbrief
python -m pip install .
crashbrief examples/demo.log --format html -o demo-report.html
```

Installation can download build tools; report generation itself does not make network requests. This project is not published to PyPI, so use the repository installation command above.

## What it does

| Feature | Behavior |
| --- | --- |
| Log input | Explicit files or piped UTF-8 stdin; up to 20 files and 2 MiB combined |
| Secret redaction | Private keys, common token shapes, credentials, authorization headers, cookies, email addresses, home directory names |
| Custom policy | Exact-match literals from a TOML config or a private text file |
| Overlap handling | Match source text first, merge overlapping spans, then substitute once |
| Error grouping | Strip leading ISO timestamps before counting duplicate error lines |
| Observed signals | Connection refused, import failures, permission errors, timeouts, OOM, full disks, DNS failures |
| Stack frames | Extract Python and JavaScript frame locations, capped at 20 |
| Report formats | Markdown for issues, self-contained HTML for humans, versioned JSON for tools |
| Baseline comparison | New/resolved built-in signals and changes in the top five error lines |
| CI gates | Nonzero exit on matched redactions or recognized error lines |
| Data boundaries | No environment collection, subprocess execution, recursive scanning, telemetry, or reversible secret map in output |
| File handling | New output files only; never overwrite an input or existing report |

## Everyday workflows

### Prepare a bug report

```sh
crashbrief app.log --title "Checkout fails after deployment" -o issue.md
```

The report includes placeholders for expected behavior, actual behavior, reproduction steps, and recent changes. Add those details, review the redactions, then share it yourself. CrashBrief does not post issues or send data to an AI provider.

### Pipe a log without creating another raw copy

```sh
cat app.log | crashbrief --format markdown
```

PowerShell with explicit UTF-8 bytes:

```powershell
crashbrief .\app.log --format html -o .\report.html
```

### Combine service logs

```sh
crashbrief api.log worker.log --title "Payment investigation" -o payment.md
```

Inputs are labelled `input 1`, `input 2`, and so on; source filenames are not included. Evidence line numbers refer to the combined, normalized, redacted log in the report. Removing control codes or a multiline private key can change original line numbers.

### Add project-specific strings to redact

Create a local configuration file:

```toml
title = "Checkout worker incident"
redact = ["checkout.internal.example", "customer-demo-42"]
```

```sh
crashbrief app.log --config crashbrief.toml -o report.md
```

For a private list of exact values, use `--redact-file private-values.txt` (one value per line). Both sources combine. Up to 100 literals, each at most 4096 characters, are accepted. These are literal matches, not executable regexes. Config files are read only when explicitly supplied. Do not commit real secrets in a config or pass them on the command line.

### Check what changed after a fix

```sh
crashbrief before.log --format json -o before.json
crashbrief after.log --compare before.json --format html -o comparison.html
```

Comparison uses built-in signal codes and the five most frequent redacted error lines. Placeholder numbers are normalized between reports. It is intentionally a bounded summary rather than a complete log diff. Timestamp normalization supports leading ISO dates; other prefixes remain part of the error text.

### Run in CI

```sh
crashbrief build.log --fail-on-error --format json -o build-report.json
crashbrief diagnostic.log --fail-on-redaction -o reviewed-report.md
```

The report is written before a gate returns a nonzero exit code. If both gates match, the redaction exit code takes precedence. No matches means only that the configured patterns found nothing; it does not certify that a log is secret-free or that a build passed.

| Exit code | Meaning |
| --- | --- |
| `0` | Report generated, requested gates did not match |
| `2` | Usage, encoding, size, configuration, read, write, or baseline error |
| `3` | `--fail-on-redaction` found redactions |
| `4` | `--fail-on-error` found recognized error lines |

```sh
crashbrief --help
crashbrief --rules
```

## Python API

```python
from crashbrief import build_report
from crashbrief.report import render

report = build_report(
    "ERROR ConnectionRefusedError: token=demo-private-value",
    title="Worker connection failure",
    literals=("private-service-name",),
)
print(report.analysis["signals"])
markdown = render(report, "markdown")
html = render(report, "html")
json_report = render(report, "json")
```

The library does not enforce CLI byte limits; callers should bound untrusted inputs. Reports are deterministic for the same input and options. Fingerprints hash only normalized, redacted log content and do not authenticate its origin.

## Architecture and verification

```text
Explicit files / stdin
        |
UTF-8 validation + input limits
        |
Normalize terminal controls -> detect spans -> union overlaps -> stable placeholders
        |
Analyze redacted text only -> optional validated baseline comparison
        |
Redacted report model -> Markdown / HTML / JSON -> exclusive output or stdout
```

The renderers never receive raw logs. HTML uses escaping and a restrictive Content Security Policy with no scripts. Markdown chooses a fence longer than any backtick run in the log so pasted text cannot close the code block. Baseline error text is redacted again using the active literal policy before it enters a comparison.

Read [the architecture notes](docs/architecture.md) for contracts, overlap resolution, data handling, limits, and extension points.

```sh
python -m pip install .
python -m unittest discover -s tests -v
```

GitHub Actions tests Python 3.11 and 3.13 on Linux and Windows, including a real installed-console-command smoke test. Tests cover credentials, overlapping detections, incomplete keys, untrusted rendering, file protection, input limits, custom policies, comparison validation, and CLI exit codes.

## Detection boundaries

Redaction is pattern-based and can miss unknown formats, obfuscated values, encoded secrets, or proprietary identifiers. It may also over-redact. Private keys without an end marker redact through the end of the input. Email and home-path matching are best effort; IP addresses, full project paths, arbitrary personal data, and generic high-entropy strings are not automatically removed. Add custom literals for your environment and review every report before sharing.

Generated Markdown is intended for a renderer that safely handles Markdown. Treat log text as untrusted data when giving it to an AI assistant; text fences do not neutralize prompt injection. Suggested checks come from fixed observable signatures, not an AI model or a confirmed root-cause diagnosis.

The HTML file has no browser editor or upload service. CrashBrief is a local CLI and Python library. It does not parse compressed archives, binary logs, or provider-specific structured schemas.

## Related work

[promptcloak](https://github.com/ezequiel0822-netizen/promptcloak) focuses on text redaction; [report-toolkit](https://ibm.github.io/report-toolkit/quick-start/) handles Node.js diagnostic reports. CrashBrief focuses on turning plain error logs into a reviewable debugging brief with evidence, cross-report comparison, and shareable output formats.
