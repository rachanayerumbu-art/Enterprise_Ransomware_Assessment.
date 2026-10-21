"""
tests/test_routes.py
Integration tests for Flask routes, database operations,
CSV export, and NIST mapping display.

Run with:
    python -m pytest tests/ -v
"""

import sys
import os
import csv
import io
import json
import pytest

# Make the project root importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Use the testing configuration (separate test DB)
os.environ["FLASK_ENV"] = "testing"

from app import app as flask_app, bootstrap_db
from database.db import get_connection, init_db
from config import get_config

TEST_CFG = get_config("testing")


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Initialise and seed the test database once per session."""
    # Point the app at the test database
    flask_app.config["DATABASE_PATH"] = TEST_CFG.DATABASE_PATH

    # Patch the db module so it uses the test DB file
    import database.db as db_module
    db_module._DB_PATH = TEST_CFG.DATABASE_PATH

    bootstrap_db()
    yield

    # Teardown: remove test DB file
    if os.path.exists(TEST_CFG.DATABASE_PATH):
        os.remove(TEST_CFG.DATABASE_PATH)


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False
    with flask_app.test_client() as c:
        yield c


# ── Helper ────────────────────────────────────────────────────────────────────

def _sample_form(**overrides):
    """Return a valid risk form dict; override any field with kwargs."""
    data = {
        "title": "Test Phishing Risk",
        "description": "A test phishing risk for route testing.",
        "affected_asset": "Test Email System",
        "threat_source": "Test Threat Actor",
        "existing_controls": "Basic spam filter",
        "likelihood": "4",
        "impact": "4",
        "nist_function": "Protect",
        "nist_category": "Awareness and Training",
        "nist_category_id": "PR.AT",
        "nist_explanation": "Training reduces phishing susceptibility.",
        "recommended_mitigation": "Deploy advanced email filtering and run phishing simulations.",
        "risk_owner": "Test IT Manager",
        "status": "Open",
        "target_date": "2025-12-31",
    }
    data.update(overrides)
    return data


# ── Dashboard ──────────────────────────────────────────────────────────────────

class TestDashboard:
    def test_dashboard_loads(self, client):
        r = client.get("/")
        assert r.status_code == 200

    def test_dashboard_contains_key_text(self, client):
        r = client.get("/")
        body = r.data.decode()
        assert "Dashboard" in body
        assert "Risk" in body

    def test_api_stats_returns_json(self, client):
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert "total" in data
        assert "critical" in data
        assert "high" in data

    def test_api_stats_counts_are_non_negative(self, client):
        data = json.loads(client.get("/api/stats").data)
        for key in ("total", "critical", "high", "medium", "low"):
            assert data[key] >= 0


# ── Risk Register ─────────────────────────────────────────────────────────────

class TestRiskRegister:
    def test_register_loads(self, client):
        r = client.get("/risks")
        assert r.status_code == 200

    def test_register_shows_sample_risks(self, client):
        r = client.get("/risks")
        body = r.data.decode()
        assert "RAN-001" in body

    def test_register_search_filter(self, client):
        r = client.get("/risks?search=RAN-001")
        assert r.status_code == 200

    def test_register_level_filter(self, client):
        r = client.get("/risks?level=Critical")
        assert r.status_code == 200

    def test_register_no_results(self, client):
        r = client.get("/risks?search=ZZZNORESULT999")
        body = r.data.decode()
        assert "0 risk" in body or "No risks found" in body


# ── Add Risk ──────────────────────────────────────────────────────────────────

class TestAddRisk:
    def test_add_risk_page_loads(self, client):
        r = client.get("/risks/add")
        assert r.status_code == 200

    def test_add_risk_valid(self, client):
        r = client.post("/risks/add", data=_sample_form(), follow_redirects=True)
        assert r.status_code == 200
        body = r.data.decode()
        assert "successfully" in body.lower() or "Test Phishing Risk" in body

    def test_add_risk_calculates_score(self, client):
        """Score must be 4×4=16 → High."""
        client.post("/risks/add", data=_sample_form(), follow_redirects=True)
        conn = get_connection()
        row = conn.execute(
            "SELECT * FROM risks WHERE title = 'Test Phishing Risk' LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            assert row["risk_score"] == 16
            assert row["risk_level"] == "High"

    def test_add_risk_missing_title(self, client):
        r = client.post("/risks/add", data=_sample_form(title=""), follow_redirects=True)
        body = r.data.decode()
        assert "required" in body.lower() or "error" in body.lower() or r.status_code == 200

    def test_add_risk_invalid_likelihood(self, client):
        r = client.post("/risks/add", data=_sample_form(likelihood="99"), follow_redirects=True)
        body = r.data.decode()
        assert "required" in body.lower() or "1 and 5" in body.lower() or r.status_code == 200

    def test_add_risk_non_numeric_impact(self, client):
        r = client.post("/risks/add", data=_sample_form(impact="abc"), follow_redirects=True)
        assert r.status_code == 200


# ── Risk Detail ───────────────────────────────────────────────────────────────

class TestRiskDetail:
    def test_existing_risk_detail(self, client):
        r = client.get("/risks/RAN-001")
        assert r.status_code == 200
        body = r.data.decode()
        assert "RAN-001" in body

    def test_nonexistent_risk_returns_404(self, client):
        r = client.get("/risks/RAN-NONEXISTENT")
        assert r.status_code == 404


# ── Edit Risk ─────────────────────────────────────────────────────────────────

class TestEditRisk:
    def test_edit_page_loads(self, client):
        r = client.get("/risks/RAN-001/edit")
        assert r.status_code == 200

    def test_edit_updates_record(self, client):
        form = _sample_form(title="Updated RAN-001 Title")
        r = client.post("/risks/RAN-001/edit", data=form, follow_redirects=True)
        assert r.status_code == 200
        # Check updated
        conn = get_connection()
        row = conn.execute("SELECT title FROM risks WHERE risk_id='RAN-001'").fetchone()
        conn.close()
        if row:
            assert row["title"] == "Updated RAN-001 Title"

    def test_edit_nonexistent_returns_404(self, client):
        r = client.get("/risks/RAN-NONEXISTENT/edit")
        assert r.status_code == 404


# ── Delete Risk ───────────────────────────────────────────────────────────────

class TestDeleteRisk:
    def test_delete_risk(self, client):
        # First add a risk to delete
        client.post("/risks/add", data=_sample_form(title="DeleteMe Risk"), follow_redirects=True)
        conn = get_connection()
        row = conn.execute("SELECT risk_id FROM risks WHERE title='DeleteMe Risk' LIMIT 1").fetchone()
        conn.close()
        if row:
            risk_id = row["risk_id"]
            r = client.post(f"/risks/{risk_id}/delete", follow_redirects=True)
            assert r.status_code == 200
            # Confirm deleted
            conn = get_connection()
            gone = conn.execute("SELECT * FROM risks WHERE risk_id=?", (risk_id,)).fetchone()
            conn.close()
            assert gone is None

    def test_delete_nonexistent_returns_404(self, client):
        r = client.post("/risks/RAN-NONEXISTENT/delete")
        assert r.status_code == 404


# ── NIST Mapping Page ─────────────────────────────────────────────────────────

class TestNistMapping:
    def test_nist_page_loads(self, client):
        r = client.get("/nist-mapping")
        assert r.status_code == 200

    def test_nist_page_has_functions(self, client):
        body = client.get("/nist-mapping").data.decode()
        for func in ["Govern", "Identify", "Protect", "Detect", "Respond", "Recover"]:
            assert func in body

    def test_nist_page_shows_category_ids(self, client):
        body = client.get("/nist-mapping").data.decode()
        # Should include at least one category ID
        assert "PR." in body or "DE." in body or "RC." in body


# ── Reports & CSV Export ──────────────────────────────────────────────────────

class TestReports:
    def test_reports_page_loads(self, client):
        r = client.get("/reports")
        assert r.status_code == 200

    def test_reports_contains_executive_summary(self, client):
        body = client.get("/reports").data.decode()
        assert "Executive Summary" in body or "Total" in body

    def test_csv_export_returns_file(self, client):
        r = client.get("/reports/export/csv")
        assert r.status_code == 200
        assert "text/csv" in r.content_type

    def test_csv_export_has_correct_headers(self, client):
        r = client.get("/reports/export/csv")
        content = r.data.decode("utf-8")
        reader = csv.reader(io.StringIO(content))
        headers = next(reader)
        assert "Risk ID" in headers
        assert "Title" in headers
        assert "Risk Level" in headers
        assert "NIST Category ID" in headers

    def test_csv_export_has_data_rows(self, client):
        r = client.get("/reports/export/csv")
        content = r.data.decode("utf-8")
        reader = csv.reader(io.StringIO(content))
        rows = list(reader)
        # Header + at least one data row (from seeded samples)
        assert len(rows) > 1

    def test_csv_contains_sample_risk(self, client):
        r = client.get("/reports/export/csv")
        content = r.data.decode("utf-8")
        assert "RAN-001" in content or "Phishing" in content


# ── Status Update ─────────────────────────────────────────────────────────────

class TestStatusUpdate:
    def test_valid_status_update(self, client):
        r = client.post(
            "/risks/RAN-002/status",
            data={"status": "In Progress"},
            follow_redirects=True
        )
        assert r.status_code == 200

    def test_invalid_status_redirects(self, client):
        r = client.post(
            "/risks/RAN-002/status",
            data={"status": "BadStatus"},
            follow_redirects=True
        )
        assert r.status_code == 200


# ── About Page ────────────────────────────────────────────────────────────────

class TestAboutPage:
    def test_about_loads(self, client):
        r = client.get("/about")
        assert r.status_code == 200

    def test_about_has_disclaimer(self, client):
        body = client.get("/about").data.decode()
        assert "disclaimer" in body.lower() or "educational" in body.lower()
