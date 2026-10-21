"""
modules/report_generator.py
CSV and printable report generation for the
Enterprise Ransomware Risk Assessment System.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime


# --------------------------------------------------------------------------- #
#  CSV Export                                                                   #
# --------------------------------------------------------------------------- #

CSV_HEADERS = [
    "Risk ID",
    "Title",
    "Description",
    "Affected Asset",
    "Threat Source",
    "Existing Controls",
    "Likelihood",
    "Impact",
    "Risk Score",
    "Risk Level",
    "NIST Function",
    "NIST Category ID",
    "NIST Category",
    "Recommended Mitigation",
    "Risk Owner",
    "Status",
    "Target Date",
    "Sample Record",
    "Created At",
    "Updated At",
]


def risks_to_csv(risks: list) -> str:
    """
    Convert a list of risk row-objects (sqlite3.Row or dict-like) to a
    CSV string.  Returns the CSV as a UTF-8 string ready to be sent as a
    file download.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)

    # Header row
    writer.writerow(CSV_HEADERS)

    for r in risks:
        # sqlite3.Row supports both index and key access
        row = dict(r) if hasattr(r, "keys") else r
        writer.writerow([
            row.get("risk_id", ""),
            row.get("title", ""),
            row.get("description", ""),
            row.get("affected_asset", ""),
            row.get("threat_source", ""),
            row.get("existing_controls", ""),
            row.get("likelihood", ""),
            row.get("impact", ""),
            row.get("risk_score", ""),
            row.get("risk_level", ""),
            row.get("nist_function", ""),
            row.get("nist_category_id", ""),
            row.get("nist_category", ""),
            row.get("recommended_mitigation", ""),
            row.get("risk_owner", ""),
            row.get("status", ""),
            row.get("target_date", ""),
            "Yes" if row.get("is_sample") else "No",
            row.get("created_at", ""),
            row.get("updated_at", ""),
        ])

    return output.getvalue()


# --------------------------------------------------------------------------- #
#  Report Summary Statistics                                                    #
# --------------------------------------------------------------------------- #

def build_report_summary(risks: list) -> dict:
    """
    Build a summary statistics dict from a list of risk records.
    Returned keys:
        total, critical, high, medium, low,
        open, in_progress, mitigated, accepted, closed,
        by_nist_function, generated_at
    """
    total = len(risks)
    counts: dict = {
        "total": total,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "open": 0,
        "in_progress": 0,
        "mitigated": 0,
        "accepted": 0,
        "closed": 0,
        "by_nist_function": {},
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    for r in risks:
        row = dict(r) if hasattr(r, "keys") else r

        # Level counts
        level = (row.get("risk_level") or "").lower()
        if level in counts:
            counts[level] += 1

        # Status counts
        status_key = (row.get("status") or "Open").lower().replace(" ", "_")
        if status_key in counts:
            counts[status_key] += 1

        # By NIST function
        func = row.get("nist_function", "Unknown")
        counts["by_nist_function"][func] = counts["by_nist_function"].get(func, 0) + 1

    return counts
