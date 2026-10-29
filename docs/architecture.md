# Architecture

## Modules and responsibilities

| Module | Responsibility |
| --- | --- |
| `cli.py` | Argument parsing, explicit input/output, size limits, exit status |
| `config.py` | Validate an explicit UTF-8 TOML policy |
| `redact.py` | Normalize terminal text, detect sensitive spans, replace overlapping spans |
| `analyze.py` | Group errors, identify observable signatures, extract evidence and stack frames |
| `compare.py` | Validate baseline contracts and compare bounded error summaries |
| `report.py` | Build the redacted data model and render three output formats |

## Redaction pipeline

1. Normalize CRLF and CR, strip ANSI CSI / OSC sequences and selected control and bidirectional characters.
2. Find custom exact literals and built-in patterns in the normalized original text.
3. Sort candidates by their source offsets. Union overlapping spans; use rule priority to name the merged category.
4. Replace each merged span once. Equal exact span values reuse a report-local numbered placeholder.
5. Count redacted span occurrences by category. Overlapping detections count as one occurrence, not several rules firing.

This order avoids a sequential-regex failure mode: if a short custom literal is part of a longer password, redacting only the literal first can stop a later rule from recognizing the full credential. Taking the union of original spans removes the complete detected region.

The transient `Redactor` stores a value-to-placeholder dictionary only in process memory. `build_report` returns no reversible mapping. Its lifetime ends when report construction completes; Python memory is not securely erased and CrashBrief does not claim memory-forensic protection. Numbering starts fresh for each report and follows the title before the log. Quoted and unquoted source values may receive different placeholders because the exact matched spans differ.

Patterns are intentionally inspectable. They do not use remote validation, entropy scoring, machine learning, or a claim of universal secret detection. Custom strings are matched literally and use the same normalization as input.

## Analysis contract

Analysis runs after redaction. `analysis` contains:

- `line_count`, `error_lines`, and `unique_error_lines`.
- `top_errors`: at most five entries with redacted text and occurrence counts.
- `signals`: fixed codes, descriptive titles, evidence line numbers, and static next checks.
- `stack_frames`: up to 20 Python / JavaScript locations; numeric coordinates are bounded before integer conversion.

Leading ISO timestamps are removed only for duplicate-error grouping. Evidence locations still refer to the full redacted text. Log levels are heuristics, so prose containing words like “error” can count as an error line. No causal conclusion is inferred.

## Report contract

Version 1 JSON includes `schema_version`, `title`, `log`, `analysis`, `redactions`, `fingerprint`, `notice`, and optional `comparison`. The SHA-256 fingerprint is calculated from the UTF-8 redacted log, not from the original secret-bearing input. It identifies report content but is not a signature or an attestation.

Markdown encodes untrusted log and error text in dynamically sized code fences. HTML applies `html.escape` to user-derived fields, includes no scripts or remote assets, and declares a restrictive CSP. Both expose the redaction review notice. JSON uses the standard encoder. Renderers consume only a redacted model; callers that manually construct a `Report` are responsible for its contents.

## Baseline comparison

Only schema version 1 is accepted. Error lists, counts, and built-in signal codes are validated. Baseline error strings are re-redacted using the current custom literals. Placeholder numbering is normalized to avoid false changes caused solely by numbering differences. The result compares signature sets and counters over the top five error lines, not complete log histories.

This design has deliberate limits: a line moving into or out of the top five can look like an increase or decrease, and different hidden secret values can compare as equivalent. Changes in configuration can also change grouping. The output includes its scope so consumers do not treat it as an exhaustive diff.

## I/O and resource limits

| Input | CLI limit |
| --- | --- |
| Combined log files / stdin | 2 MiB |
| Explicit source count | 20 |
| Stdin occurrences | 1 |
| TOML or custom-literal file | 64 KiB each |
| Custom literals | 100 combined, at most 4096 characters each |
| Baseline JSON | 16 MiB |
| Title | 1–200 characters |

Reads are bounded before decoding. Invalid UTF-8 fails explicitly; a UTF-8 BOM is supported. Files are never discovered recursively and environment variables are never collected. Source filenames are replaced by ordinal labels in multi-input reports. Output uses an exclusive file create; existing outputs, inputs, and symlinks at an existing output path are not replaced. On POSIX, new output mode is requested as `0600`; Windows uses inherited ACLs. Error messages for filesystem failures omit paths and raw exceptions.

The library API is intentionally independent from CLI limits. A service embedding it must apply request-size, concurrency, and time limits of its own. The CLI operates in memory and is intended for small incident excerpts, not unbounded log streams.

## Extension points

Add a built-in redaction detector as a `Rule` with a compiled pattern and optional capture group. Add a troubleshooting signal to `SIGNATURES` with a stable code and a concrete, non-destructive next check. Add fixtures for positive, negative, overlap, and renderer cases before extending behavior. New report contract shapes should change `schema_version`; baseline readers must fail explicitly on unsupported versions.

## Deliberate exclusions

No uploads, account system, telemetry, external AI calls, command execution, automatic remediation, repository scanning, environment harvesting, or package registry publication. Those are separate products and are not silently implied by a debugging report workflow.
