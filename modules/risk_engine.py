"""
modules/risk_engine.py
Risk scoring and classification logic for the
Enterprise Ransomware Risk Assessment System.

Risk Score  = Likelihood (1-5) × Impact (1-5)
Risk Level  :
    1–4   → Low
    5–9   → Medium
    10–16 → High
    17–25 → Critical
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
#  Constants                                                                   #
# --------------------------------------------------------------------------- #

RISK_LEVEL_LOW = "Low"
RISK_LEVEL_MEDIUM = "Medium"
RISK_LEVEL_HIGH = "High"
RISK_LEVEL_CRITICAL = "Critical"

RISK_LEVEL_COLORS: dict[str, str] = {
    RISK_LEVEL_LOW: "#22c55e",       # green
    RISK_LEVEL_MEDIUM: "#eab308",    # yellow
    RISK_LEVEL_HIGH: "#f97316",      # orange
    RISK_LEVEL_CRITICAL: "#ef4444",  # red
}

VALID_SCORES = range(1, 6)  # 1 – 5 inclusive


# --------------------------------------------------------------------------- #
#  Core Functions                                                               #
# --------------------------------------------------------------------------- #

def calculate_risk_score(likelihood: int, impact: int) -> int:
    """
    Return the risk score (Likelihood × Impact).

    Raises ValueError if either parameter is outside 1–5.
    """
    if likelihood not in VALID_SCORES:
        raise ValueError(f"Likelihood must be 1–5, got {likelihood!r}")
    if impact not in VALID_SCORES:
        raise ValueError(f"Impact must be 1–5, got {impact!r}")
    return likelihood * impact


def classify_risk(score: int) -> str:
    """
    Return the risk level string for a given numeric score.

    Raises ValueError for scores outside the valid range 1–25.
    """
    if score < 1 or score > 25:
        raise ValueError(f"Score must be 1–25, got {score!r}")
    if score <= 4:
        return RISK_LEVEL_LOW
    if score <= 9:
        return RISK_LEVEL_MEDIUM
    if score <= 16:
        return RISK_LEVEL_HIGH
    return RISK_LEVEL_CRITICAL


def assess_risk(likelihood: int, impact: int) -> dict:
    """
    Convenience wrapper: compute score + level in one call.

    Returns a dict with keys: score, level, color.
    """
    score = calculate_risk_score(likelihood, impact)
    level = classify_risk(score)
    return {
        "score": score,
        "level": level,
        "color": RISK_LEVEL_COLORS[level],
    }


def get_risk_badge_class(level: str) -> str:
    """Return the CSS badge class name for a given risk level string."""
    mapping = {
        RISK_LEVEL_LOW: "badge-low",
        RISK_LEVEL_MEDIUM: "badge-medium",
        RISK_LEVEL_HIGH: "badge-high",
        RISK_LEVEL_CRITICAL: "badge-critical",
    }
    return mapping.get(level, "badge-low")


def validate_risk_form(form_data: dict) -> list[str]:
    """
    Validate risk form fields.
    Returns a list of error message strings (empty list = no errors).
    """
    errors: list[str] = []

    required_text = [
        ("title", "Risk title"),
        ("description", "Risk description"),
        ("affected_asset", "Affected asset"),
        ("threat_source", "Threat source"),
        ("recommended_mitigation", "Recommended mitigation"),
        ("risk_owner", "Risk owner"),
        ("nist_function", "NIST CSF function"),
        ("nist_category", "NIST CSF category"),
        ("nist_category_id", "NIST CSF category ID"),
    ]

    for field, label in required_text:
        value = form_data.get(field, "").strip()
        if not value:
            errors.append(f"{label} is required.")

    for field, label in [("likelihood", "Likelihood"), ("impact", "Impact")]:
        raw = form_data.get(field, "")
        try:
            val = int(raw)
            if val not in VALID_SCORES:
                errors.append(f"{label} must be between 1 and 5.")
        except (ValueError, TypeError):
            errors.append(f"{label} must be a whole number between 1 and 5.")

    status = form_data.get("status", "")
    valid_statuses = {"Open", "In Progress", "Mitigated", "Accepted", "Closed"}
    if status not in valid_statuses:
        errors.append(f"Status must be one of: {', '.join(sorted(valid_statuses))}.")

    return errors
