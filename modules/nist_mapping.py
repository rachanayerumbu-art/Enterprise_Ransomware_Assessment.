"""
modules/nist_mapping.py
NIST Cybersecurity Framework (CSF) 2.0 reference data and helpers.

DISCLAIMER:
  The mappings here are provided for educational and planning purposes only.
  They do not constitute official NIST guidance and do not guarantee
  compliance with the NIST Cybersecurity Framework or any regulation.
  Always refer to the official NIST CSF 2.0 publication at
  https://www.nist.gov/cyberframework for authoritative information.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
#  NIST CSF 2.0 Functions                                                      #
# --------------------------------------------------------------------------- #

NIST_FUNCTIONS: dict[str, dict] = {
    "GV": {
        "name": "Govern",
        "description": (
            "Establishes and monitors the organization's cybersecurity risk "
            "management strategy, expectations, and policy."
        ),
        "color": "#7c3aed",
    },
    "ID": {
        "name": "Identify",
        "description": (
            "Develops understanding to manage cybersecurity risks to systems, "
            "people, assets, data, and capabilities."
        ),
        "color": "#2563eb",
    },
    "PR": {
        "name": "Protect",
        "description": (
            "Implements safeguards to limit or contain the impact of a "
            "potential cybersecurity event."
        ),
        "color": "#059669",
    },
    "DE": {
        "name": "Detect",
        "description": (
            "Develops and implements activities to identify the occurrence of "
            "a cybersecurity event."
        ),
        "color": "#d97706",
    },
    "RS": {
        "name": "Respond",
        "description": (
            "Develops and implements activities to take action regarding a "
            "detected cybersecurity incident."
        ),
        "color": "#dc2626",
    },
    "RC": {
        "name": "Recover",
        "description": (
            "Identifies activities to maintain plans for resilience and to "
            "restore capabilities or services impaired by a cybersecurity event."
        ),
        "color": "#0891b2",
    },
}

# --------------------------------------------------------------------------- #
#  NIST CSF 2.0 Categories (subset relevant to ransomware)                     #
# --------------------------------------------------------------------------- #

NIST_CATEGORIES: dict[str, dict] = {
    # -- Govern --
    "GV.OC": {
        "name": "Organizational Context",
        "function": "GV",
        "description": "The organizational mission is understood and informs cybersecurity risk management.",
    },
    "GV.RM": {
        "name": "Risk Management Strategy",
        "function": "GV",
        "description": "The organization's priorities, constraints, risk tolerance, and assumptions are established.",
    },
    "GV.RR": {
        "name": "Roles, Responsibilities, and Authorities",
        "function": "GV",
        "description": "Cybersecurity roles, responsibilities, and authorities are established.",
    },
    "GV.PO": {
        "name": "Policy",
        "function": "GV",
        "description": "Organizational cybersecurity policy is established, communicated, and enforced.",
    },
    "GV.SC": {
        "name": "Cybersecurity Supply Chain Risk Management",
        "function": "GV",
        "description": "Cyber supply chain risk management processes are identified, established, and managed.",
    },
    # -- Identify --
    "ID.AM": {
        "name": "Asset Management",
        "function": "ID",
        "description": "Assets (data, hardware, software, systems, facilities, people) that enable the organization to achieve business purposes are identified and managed.",
    },
    "ID.RA": {
        "name": "Risk Assessment",
        "function": "ID",
        "description": "The organization understands the cybersecurity risk to organizational operations, assets, and individuals.",
    },
    "ID.IM": {
        "name": "Improvement",
        "function": "ID",
        "description": "Improvements to organizational cybersecurity risk management processes and procedures are identified across all CSF functions.",
    },
    # -- Protect --
    "PR.AA": {
        "name": "Identity Management, Authentication, and Access Control",
        "function": "PR",
        "description": "Access to physical and logical assets is limited to authorized users, services, and hardware.",
    },
    "PR.AT": {
        "name": "Awareness and Training",
        "function": "PR",
        "description": "The organization's personnel and partners are provided cybersecurity awareness education.",
    },
    "PR.DS": {
        "name": "Data Security",
        "function": "PR",
        "description": "Data are managed consistent with the organization's risk strategy to protect the confidentiality, integrity, and availability of information.",
    },
    "PR.PS": {
        "name": "Platform Security",
        "function": "PR",
        "description": "The hardware, software (including firmware and code), and services of physical and virtual platforms are managed consistent with the organization's risk strategy.",
    },
    "PR.IR": {
        "name": "Technology Infrastructure Resilience",
        "function": "PR",
        "description": "Security architectures are managed with the organization's risk strategy to protect asset confidentiality, integrity, and availability.",
    },
    # -- Detect --
    "DE.AE": {
        "name": "Adverse Event Analysis",
        "function": "DE",
        "description": "Anomalies, indicators of compromise, and other potentially adverse events are analyzed to characterize the events.",
    },
    "DE.CM": {
        "name": "Continuous Monitoring",
        "function": "DE",
        "description": "Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events.",
    },
    # -- Respond --
    "RS.MA": {
        "name": "Incident Management",
        "function": "RS",
        "description": "Responses to detected cybersecurity incidents are managed.",
    },
    "RS.AN": {
        "name": "Incident Analysis",
        "function": "RS",
        "description": "Investigations are conducted to ensure effective response and support forensics and recovery activities.",
    },
    "RS.CO": {
        "name": "Incident Response Reporting and Communication",
        "function": "RS",
        "description": "Response activities are coordinated with internal and external stakeholders.",
    },
    "RS.MI": {
        "name": "Incident Mitigation",
        "function": "RS",
        "description": "Activities are performed to prevent expansion of an event, mitigate its effects, and resolve the incident.",
    },
    # -- Recover --
    "RC.RP": {
        "name": "Incident Recovery Plan Execution",
        "function": "RC",
        "description": "Restoration activities are performed to ensure operational availability of systems and services affected by cybersecurity incidents.",
    },
    "RC.CO": {
        "name": "Incident Recovery Communication",
        "function": "RC",
        "description": "Restoration activities are coordinated with internal and external parties.",
    },
}


# --------------------------------------------------------------------------- #
#  Helper Functions                                                             #
# --------------------------------------------------------------------------- #

def get_function_name(function_code: str) -> str:
    """Return the human-readable function name for a two-letter code."""
    info = NIST_FUNCTIONS.get(function_code, {})
    return info.get("name", function_code)


def get_category_name(category_id: str) -> str:
    """Return the human-readable category name for a category ID."""
    info = NIST_CATEGORIES.get(category_id, {})
    return info.get("name", category_id)


def get_functions_list() -> list[dict]:
    """Return a list of all NIST CSF 2.0 functions as dicts for templates."""
    return [
        {"code": code, **data}
        for code, data in NIST_FUNCTIONS.items()
    ]


def get_categories_for_function(function_code: str) -> list[dict]:
    """Return all categories belonging to the given function code."""
    return [
        {"id": cat_id, **cat_data}
        for cat_id, cat_data in NIST_CATEGORIES.items()
        if cat_data["function"] == function_code
    ]


def get_all_categories() -> list[dict]:
    """Return all categories as a flat list of dicts."""
    return [
        {"id": cat_id, **cat_data}
        for cat_id, cat_data in NIST_CATEGORIES.items()
    ]


def get_categories_by_function() -> dict[str, list[dict]]:
    """Return a dict mapping function codes to their category lists."""
    result: dict[str, list[dict]] = {code: [] for code in NIST_FUNCTIONS}
    for cat_id, cat_data in NIST_CATEGORIES.items():
        func_code = cat_data["function"]
        result[func_code].append({"id": cat_id, **cat_data})
    return result
