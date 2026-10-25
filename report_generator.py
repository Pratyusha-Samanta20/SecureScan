"""
report_generator.py — SecureScan report generation.

Produces CSV and plain-text reports from scan results.
No external dependencies beyond the Python standard library.
"""

import csv
import io
from datetime import datetime, timezone


def _now_str() -> str:
    """Return the current UTC date/time as a human-readable string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ── CSV report ────────────────────────────────────────────────────────────────

def generate_csv(scan_result: dict) -> str:
    """
    Return a CSV string representing the scan report.

    Parameters
    ----------
    scan_result : dict
        The dict returned by scanner.scan_website().

    Returns
    -------
    str
        CSV-formatted report ready for download.
    """
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")

    # Metadata rows
    writer.writerow(["SecureScan — Automated Website Security Checker"])
    writer.writerow(["Scan Date/Time", _now_str()])
    writer.writerow(["Scanned URL", scan_result.get("original_url", "")])
    writer.writerow(["Final URL", scan_result.get("final_url", "")])
    writer.writerow(["HTTP Status Code", scan_result.get("status_code", "")])
    writer.writerow([])  # blank separator

    # Column headers
    writer.writerow(["Check", "Status", "Value", "Explanation", "Recommendation"])

    for check in scan_result.get("checks", []):
        writer.writerow([
            check.get("check", ""),
            check.get("status", ""),
            check.get("value", ""),
            check.get("explanation", ""),
            check.get("recommendation", ""),
        ])

    writer.writerow([])
    writer.writerow([
        "DISCLAIMER",
        (
            "This report reflects a limited set of observable security configurations. "
            "It does not constitute a professional security audit and does not guarantee "
            "that the website is free from vulnerabilities."
        ),
    ])

    return output.getvalue()


# ── Plain-text report ─────────────────────────────────────────────────────────

def generate_text(scan_result: dict) -> str:
    """
    Return a plain-text string representing the scan report.

    Parameters
    ----------
    scan_result : dict
        The dict returned by scanner.scan_website().

    Returns
    -------
    str
        Plain-text report ready for download.
    """
    lines: list[str] = []
    sep = "=" * 60

    lines.append(sep)
    lines.append("  SecureScan — Automated Website Security Checker")
    lines.append(sep)
    lines.append(f"  Scan Date/Time : {_now_str()}")
    lines.append(f"  Scanned URL    : {scan_result.get('original_url', '')}")
    lines.append(f"  Final URL      : {scan_result.get('final_url', '')}")
    lines.append(f"  HTTP Status    : {scan_result.get('status_code', '')}")
    lines.append(sep)
    lines.append("")

    checks = scan_result.get("checks", [])
    pass_count = sum(1 for c in checks if c.get("status") == "PASS")
    warn_count = sum(1 for c in checks if c.get("status") == "WARNING")

    lines.append(f"  Total checks   : {len(checks)}")
    lines.append(f"  Passed         : {pass_count}")
    lines.append(f"  Warnings       : {warn_count}")
    lines.append("")
    lines.append(sep)
    lines.append("  FINDINGS")
    lines.append(sep)
    lines.append("")

    for check in checks:
        status = check.get("status", "")
        name = check.get("check", "")
        value = check.get("value", "")
        explanation = check.get("explanation", "")
        recommendation = check.get("recommendation", "")

        lines.append(f"  [{status}] {name}")
        lines.append(f"    Value          : {value}")
        lines.append(f"    Explanation    : {explanation}")
        if recommendation:
            lines.append(f"    Recommendation : {recommendation}")
        lines.append("")

    lines.append(sep)
    lines.append("  DISCLAIMER")
    lines.append(sep)
    lines.append("")
    lines.append(
        "  This report reflects a limited set of observable security"
    )
    lines.append(
        "  configurations. It does not constitute a professional security"
    )
    lines.append(
        "  audit and does not guarantee that the website is free from"
    )
    lines.append("  vulnerabilities.")
    lines.append("")
    lines.append(sep)

    return "\n".join(lines)
