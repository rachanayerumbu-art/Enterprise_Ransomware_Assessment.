# Enterprise Ransomware Assessment 

> **Version:** 1.0.0  
> **Framework:** NIST Cybersecurity Framework (CSF) 2.0  
> **Stack:** Python · Flask · SQLite · Chart.js  

---

## Project Overview

The Enterprise Ransomware  Assessment is a web application that helps security administrators:

1. Identify common ransomware-related risks
2. Assess their likelihood and impact
3. Calculate a risk score and assign a risk level
4. Map risks to the NIST CSF 2.0 framework
5. Record recommended security controls
6. Track mitigation progress and ownership
7. Generate and export risk assessment reports

---

## Problem Statement

Ransomware remains one of the most financially and operationally damaging cyber threats. Many organisations lack a structured process to identify, score, and track ransomware-specific risks. Without a centralised register, security teams cannot prioritise remediation, assign accountability, or demonstrate risk-informed decision-making to management.

---

## Objectives

| # | Objective |
|---|-----------|
| 1 | Provide a structured risk identification process covering common ransomware attack vectors |
| 2 | Calculate quantitative risk scores using the Likelihood × Impact matrix |
| 3 | Map every risk to a relevant NIST CSF 2.0 function and category |
| 4 | Recommend practical defensive controls for each risk |
| 5 | Enable tracking of risk status, ownership, and target resolution dates |
| 6 | Generate exportable reports (CSV + printable) from live database records |

---

## Features

- **Dashboard** — live statistics, risk distribution charts (Chart.js), top-scored risks
- **Risk Register** — searchable, filterable table with full CRUD operations
- **Add / Edit Risk Form** — client-side score calculation preview, NIST category selector
- **Risk Detail View** — complete risk record with quick status update
- **NIST CSF 2.0 Mapping Page** — all risks mapped to framework functions and categories
- **Reports Page** — executive summary, risk distribution charts, full register table
- **CSV Export** — download the full risk register as a spreadsheet
- **Print-friendly Report** — browser print function generates a clean report
- **12 Pre-loaded Sample Risks** — realistic fictional ransomware scenarios
- **Input Validation** — server-side and client-side validation for all forms
- **Audit Log** — every create, update, and delete action is recorded

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.x, Flask 3.0 |
| Database | SQLite 3 (via Python `sqlite3` stdlib) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Charts | Chart.js 4 (CDN) |
| Framework | NIST Cybersecurity Framework 2.0 |
| Testing | pytest |

No paid APIs or cloud services are required.

---

## NIST Cybersecurity Framework 2.0

The NIST CSF 2.0 (published February 2024) organises cybersecurity activities into **six core functions**:

| Code | Function | Purpose |
|------|----------|---------|
| GV | **Govern** | Establishes and monitors cybersecurity risk management strategy and policy |
| ID | **Identify** | Develops understanding to manage risk to systems, people, assets, and data |
| PR | **Protect** | Implements safeguards to limit or contain cybersecurity event impacts |
| DE | **Detect** | Develops and implements activities to identify cybersecurity events |
| RS | **Respond** | Takes action regarding detected cybersecurity incidents |
| RC | **Recover** | Maintains plans for resilience and restores capabilities after incidents |

Each function contains multiple **categories** (e.g., `PR.AT` = Awareness and Training). ERRAS maps each risk record to the most relevant function and category.

> **Reference:** [https://www.nist.gov/cyberframework](https://www.nist.gov/cyberframework)

---

## Risk Scoring Methodology

```
Risk Score = Likelihood (1–5) × Impact (1–5)
```

| Score Range | Risk Level | Description |
|-------------|-----------|-------------|
| 1 – 4 | 🟢 Low | Acceptable risk; monitor periodically |
| 5 – 9 | 🟡 Medium | Requires planned remediation |
| 10 – 16 | 🟠 High | Urgent action required |
| 17 – 25 | 🔴 Critical | Immediate action required |

**Likelihood Scale:**
| Score | Label |
|-------|-------|
| 1 | Rare |
| 2 | Unlikely |
| 3 | Possible |
| 4 | Likely |
| 5 | Almost Certain |

**Impact Scale:**
| Score | Label |
|-------|-------|
| 1 | Negligible |
| 2 | Minor |
| 3 | Moderate |
| 4 | Major |
| 5 | Catastrophic |

---

## Project Folder Structure

```
enterprise-ransomware-assessment/
├── app.py                     ← Flask application entry point
├── config.py                  ← Environment configuration
├── requirements.txt           ← Python dependencies
├── README.md                  ← This file
├── database/
│   ├── __init__.py
│   ├── db.py                  ← DB connection, init, audit logging
│   └── schema.sql             ← SQLite schema (CREATE TABLE statements)
├── modules/
│   ├── __init__.py
│   ├── risk_engine.py         ← Scoring, classification, validation
│   ├── nist_mapping.py        ← NIST CSF 2.0 reference data and helpers
│   ├── report_generator.py    ← CSV export and summary statistics
│   └── sample_data.py         ← 12 pre-loaded illustrative risk records
├── templates/
│   ├── base.html              ← Shared layout (sidebar, topbar, flash messages)
│   ├── dashboard.html         ← Main dashboard with charts
│   ├── risk_register.html     ← Risk register table with search/filter
│   ├── add_risk.html          ← Add new risk form
│   ├── edit_risk.html         ← Edit existing risk form
│   ├── risk_detail.html       ← Full risk detail view
│   ├── nist_mapping.html      ← NIST CSF 2.0 mapping page
│   ├── reports.html           ← Reports and export page
│   ├── about.html             ← About and documentation page
│   ├── 404.html               ← Not found error page
│   └── 500.html               ← Server error page
├── static/
│   ├── css/
│   │   └── style.css          ← Application stylesheet (dark navy theme)
│   └── js/
│       ├── dashboard.js       ← Dashboard auto-refresh
│       └── risk_form.js       ← Score calculator and NIST category filter
└── tests/
    ├── __init__.py
    ├── test_risk_engine.py    ← Unit tests for scoring logic
    └── test_routes.py         ← Integration tests for Flask routes
```

---

## Windows Installation Instructions

### Prerequisites

- Python 3.10 or later — download from [python.org](https://www.python.org/downloads/)
- VS Code — download from [code.visualstudio.com](https://code.visualstudio.com/)
- Python extension for VS Code (optional but recommended)

### Step 1: Open the Project in VS Code

```
File → Open Folder → select enterprise-ransomware-assessment
```

### Step 2: Open the Integrated Terminal

```
Terminal → New Terminal   (or Ctrl + `)
```

### Step 3: Create and Activate a Virtual Environment

```powershell
python -m venv venv
venv\Scripts\activate
```

You should see `(venv)` at the start of the prompt.

### Step 4: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 5: Run the Application

```powershell
python app.py
```

Expected output:
```
 * Running on http://0.0.0.0:5000
 * Debug mode: on
```

### Step 6: Open in Browser

Navigate to: **http://127.0.0.1:5000**

The database is created automatically on first run and the 12 sample risks are loaded.

---

## Running Tests

With the virtual environment activated:

```powershell
python -m pytest tests/ -v
```

To run only unit tests:

```powershell
python -m pytest tests/test_risk_engine.py -v
```

To run only integration tests:

```powershell
python -m pytest tests/test_routes.py -v
```

---

## Sample Demonstration Workflow

This is a suggested walkthrough for demonstrating the application to a lecturer or examiner:

1. **Start the app** — `python app.py` → open http://127.0.0.1:5000
2. **Dashboard** — show stat cards (total, critical, high, medium, low risks), three Chart.js charts
3. **Risk Register** — browse the 12 pre-loaded sample risks; use search to find "phishing"; filter by "Critical" level
4. **Risk Detail** — click View on RAN-001; explain the score (5×5=25, Critical), NIST mapping, and mitigation recommendation
5. **Add a Risk** — click Add Risk; fill in the form; observe the live score calculation as Likelihood/Impact are selected; save and verify the new risk appears in the register
6. **Edit a Risk** — edit RAN-002; change the status to "In Progress"; save
7. **NIST Mapping** — navigate to NIST Mapping; explain the six CSF 2.0 functions and the mapping table
8. **Reports** — navigate to Reports; show the executive summary and distribution charts; click Export CSV to download; click Print Report
9. **Run Tests** — in the terminal: `python -m pytest tests/ -v`


A: Activate the virtual environment and run `python -m pytest tests/ -v`.



