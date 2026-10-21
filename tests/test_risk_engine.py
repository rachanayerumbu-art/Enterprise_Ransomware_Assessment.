"""
tests/test_risk_engine.py
Unit tests for modules/risk_engine.py

Run with:
    python -m pytest tests/ -v
"""

import sys
import os
import pytest

# Make the project root importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.risk_engine import (
    calculate_risk_score,
    classify_risk,
    assess_risk,
    validate_risk_form,
    get_risk_badge_class,
    RISK_LEVEL_LOW, RISK_LEVEL_MEDIUM, RISK_LEVEL_HIGH, RISK_LEVEL_CRITICAL,
)


# ── calculate_risk_score ──────────────────────────────────────────────────────

class TestCalculateRiskScore:
    def test_minimum(self):
        assert calculate_risk_score(1, 1) == 1

    def test_maximum(self):
        assert calculate_risk_score(5, 5) == 25

    def test_typical(self):
        assert calculate_risk_score(4, 4) == 16

    def test_asymmetric(self):
        assert calculate_risk_score(3, 5) == 15
        assert calculate_risk_score(5, 3) == 15

    def test_invalid_likelihood_zero(self):
        with pytest.raises(ValueError):
            calculate_risk_score(0, 3)

    def test_invalid_likelihood_six(self):
        with pytest.raises(ValueError):
            calculate_risk_score(6, 3)

    def test_invalid_impact_zero(self):
        with pytest.raises(ValueError):
            calculate_risk_score(3, 0)

    def test_invalid_impact_six(self):
        with pytest.raises(ValueError):
            calculate_risk_score(3, 6)

    def test_invalid_negative(self):
        with pytest.raises(ValueError):
            calculate_risk_score(-1, 3)

    def test_invalid_float_like_string(self):
        with pytest.raises((ValueError, TypeError)):
            calculate_risk_score("3", 2)  # type: ignore


# ── classify_risk ─────────────────────────────────────────────────────────────

class TestClassifyRisk:
    # Boundary tests
    def test_score_1_is_low(self):
        assert classify_risk(1) == RISK_LEVEL_LOW

    def test_score_4_is_low(self):
        assert classify_risk(4) == RISK_LEVEL_LOW

    def test_score_5_is_medium(self):
        assert classify_risk(5) == RISK_LEVEL_MEDIUM

    def test_score_9_is_medium(self):
        assert classify_risk(9) == RISK_LEVEL_MEDIUM

    def test_score_10_is_high(self):
        assert classify_risk(10) == RISK_LEVEL_HIGH

    def test_score_16_is_high(self):
        assert classify_risk(16) == RISK_LEVEL_HIGH

    def test_score_17_is_critical(self):
        assert classify_risk(17) == RISK_LEVEL_CRITICAL

    def test_score_25_is_critical(self):
        assert classify_risk(25) == RISK_LEVEL_CRITICAL

    def test_invalid_zero(self):
        with pytest.raises(ValueError):
            classify_risk(0)

    def test_invalid_26(self):
        with pytest.raises(ValueError):
            classify_risk(26)

    def test_invalid_negative(self):
        with pytest.raises(ValueError):
            classify_risk(-5)


# ── assess_risk ───────────────────────────────────────────────────────────────

class TestAssessRisk:
    def test_returns_dict(self):
        result = assess_risk(3, 3)
        assert isinstance(result, dict)
        assert "score" in result
        assert "level" in result
        assert "color" in result

    def test_critical_combo(self):
        r = assess_risk(5, 5)
        assert r["score"] == 25
        assert r["level"] == RISK_LEVEL_CRITICAL

    def test_low_combo(self):
        r = assess_risk(1, 2)
        assert r["score"] == 2
        assert r["level"] == RISK_LEVEL_LOW

    def test_medium_combo(self):
        r = assess_risk(3, 2)
        assert r["score"] == 6
        assert r["level"] == RISK_LEVEL_MEDIUM

    def test_high_combo(self):
        r = assess_risk(4, 3)
        assert r["score"] == 12
        assert r["level"] == RISK_LEVEL_HIGH


# ── get_risk_badge_class ──────────────────────────────────────────────────────

class TestGetRiskBadgeClass:
    def test_critical(self):
        assert get_risk_badge_class("Critical") == "badge-critical"

    def test_high(self):
        assert get_risk_badge_class("High") == "badge-high"

    def test_medium(self):
        assert get_risk_badge_class("Medium") == "badge-medium"

    def test_low(self):
        assert get_risk_badge_class("Low") == "badge-low"

    def test_unknown_defaults_to_low(self):
        assert get_risk_badge_class("Unknown") == "badge-low"


# ── validate_risk_form ────────────────────────────────────────────────────────

class TestValidateRiskForm:
    def _valid_form(self):
        return {
            "title": "Test Risk",
            "description": "A test description",
            "affected_asset": "Server",
            "threat_source": "External Actor",
            "recommended_mitigation": "Apply patches",
            "risk_owner": "IT Manager",
            "nist_function": "Protect",
            "nist_category": "Platform Security",
            "nist_category_id": "PR.PS",
            "likelihood": "3",
            "impact": "4",
            "status": "Open",
        }

    def test_valid_form_no_errors(self):
        errors = validate_risk_form(self._valid_form())
        assert errors == []

    def test_missing_title(self):
        form = self._valid_form()
        form["title"] = ""
        errors = validate_risk_form(form)
        assert any("title" in e.lower() for e in errors)

    def test_missing_description(self):
        form = self._valid_form()
        form["description"] = "  "
        errors = validate_risk_form(form)
        assert any("description" in e.lower() for e in errors)

    def test_likelihood_zero(self):
        form = self._valid_form()
        form["likelihood"] = "0"
        errors = validate_risk_form(form)
        assert len(errors) > 0

    def test_likelihood_six(self):
        form = self._valid_form()
        form["likelihood"] = "6"
        errors = validate_risk_form(form)
        assert len(errors) > 0

    def test_impact_non_numeric(self):
        form = self._valid_form()
        form["impact"] = "abc"
        errors = validate_risk_form(form)
        assert len(errors) > 0

    def test_invalid_status(self):
        form = self._valid_form()
        form["status"] = "Unknown Status"
        errors = validate_risk_form(form)
        assert any("status" in e.lower() for e in errors)

    def test_missing_nist_function(self):
        form = self._valid_form()
        form["nist_function"] = ""
        errors = validate_risk_form(form)
        assert len(errors) > 0

    def test_multiple_errors(self):
        form = self._valid_form()
        form["title"] = ""
        form["risk_owner"] = ""
        form["likelihood"] = "10"
        errors = validate_risk_form(form)
        assert len(errors) >= 3
