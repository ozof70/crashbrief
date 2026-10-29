"""Compare observable error signatures in two reports, never raw secret values."""
from collections import Counter
import re

from .redact import Redactor
from .analyze import SIGNATURES


def compare_reports(current: dict, baseline: dict, literals: tuple[str, ...] = ()) -> dict:
    """Accept the versioned JSON report contract and return a bounded delta."""
    def extract(report):
        if not isinstance(report, dict) or report.get("schema_version") != 1:
            raise ValueError("Baseline must be a CrashBrief JSON report with schema_version 1")
        analysis = report.get("analysis")
        if not isinstance(analysis, dict):
            raise ValueError("Baseline has invalid analysis")
        errors, signals = analysis.get("top_errors"), analysis.get("signals")
        if not isinstance(errors, list) or len(errors) > 5 or not isinstance(signals, list) or len(signals) > 20:
            raise ValueError("Baseline has invalid error or signal lists")
        counter = Counter()
        redactor = Redactor(literals)
        for item in errors:
            if not isinstance(item, dict) or not isinstance(item.get("text"), str) or len(item["text"]) > 2_097_152:
                raise ValueError("Baseline has an invalid error line")
            count = item.get("count")
            if type(count) is not int or not 1 <= count <= 2_097_152:
                raise ValueError("Baseline has an invalid error count")
            # Placeholder numbering is report-local, so normalize it for comparison.
            line = re.sub(r"\[REDACTED_\d+\]", "[REDACTED]", redactor.redact(item["text"]))
            counter[line] += count
        codes = set()
        for signal in signals:
            if not isinstance(signal, dict) or not isinstance(signal.get("code"), str):
                raise ValueError("Baseline has an invalid signal")
            if not re.fullmatch(r"[a-z_]{1,64}", signal["code"]):
                raise ValueError("Baseline has an invalid signal code")
            if signal["code"] not in {entry[0] for entry in SIGNATURES}:
                raise ValueError("Baseline contains an unknown signal code")
            codes.add(signal["code"])
        return counter, codes

    before, old_signals = extract(baseline)
    after, new_signals = extract(current)
    return {
        "new_signals": sorted(new_signals - old_signals),
        "resolved_signals": sorted(old_signals - new_signals),
        "increased_errors": [{"text": t, "delta": n} for t, n in (after-before).most_common(5)],
        "decreased_errors": [{"text": t, "delta": n} for t, n in (before-after).most_common(5)],
        "scope": "Compares the five most frequent redacted error lines and built-in signatures; not a full-log diff.",
    }
