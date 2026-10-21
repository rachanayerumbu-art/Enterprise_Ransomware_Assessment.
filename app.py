"""
app.py
Main Flask application for the
Enterprise Ransomware Risk Assessment System.

Run with:
    python app.py
"""

from __future__ import annotations

import os
import sys
import io
import csv

# Make sure sibling packages resolve when run from the project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    make_response,
    abort,
)

from config import get_config
from database.db import get_connection, init_db, log_action
from modules.risk_engine import (
    calculate_risk_score,
    classify_risk,
    assess_risk,
    validate_risk_form,
    get_risk_badge_class,
)
from modules.nist_mapping import (
    NIST_FUNCTIONS,
    NIST_CATEGORIES,
    get_functions_list,
    get_all_categories,
    get_categories_by_function,
    get_function_name,
    get_category_name,
)
from modules.report_generator import risks_to_csv, build_report_summary
from modules.sample_data import SAMPLE_RISKS

# --------------------------------------------------------------------------- #
#  Application Factory                                                          #
# --------------------------------------------------------------------------- #

def create_app(env: str = "development") -> Flask:
    cfg = get_config(env)
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )
    app.config.from_object(cfg)
    app.secret_key = cfg.SECRET_KEY

    # Expose helpers to all templates
    app.jinja_env.globals.update(
        get_risk_badge_class=get_risk_badge_class,
        get_function_name=get_function_name,
        get_category_name=get_category_name,
        nist_functions=NIST_FUNCTIONS,
        nist_categories=NIST_CATEGORIES,
        APP_NAME=cfg.APP_NAME,
        APP_VERSION=cfg.APP_VERSION,
    )

    return app


app = create_app(os.environ.get("FLASK_ENV", "development"))


# --------------------------------------------------------------------------- #
#  Database Bootstrap                                                           #
# --------------------------------------------------------------------------- #

def bootstrap_db() -> None:
    """Initialise schema and seed sample data if the table is empty."""
    init_db()
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM risks").fetchone()[0]
        if count == 0:
            _seed_sample_data(conn)
    finally:
        conn.close()


def _seed_sample_data(conn) -> None:
    for r in SAMPLE_RISKS:
        score = calculate_risk_score(r["likelihood"], r["impact"])
        level = classify_risk(score)
        conn.execute(
            """INSERT OR IGNORE INTO risks
               (risk_id, title, description, affected_asset, threat_source,
                existing_controls, likelihood, impact, risk_score, risk_level,
                nist_function, nist_category, nist_category_id, nist_explanation,
                recommended_mitigation, risk_owner, status, target_date, is_sample)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                r["risk_id"], r["title"], r["description"],
                r["affected_asset"], r["threat_source"],
                r.get("existing_controls", ""), r["likelihood"], r["impact"],
                score, level,
                r["nist_function"], r["nist_category"], r["nist_category_id"],
                r.get("nist_explanation", ""), r["recommended_mitigation"],
                r["risk_owner"], r["status"], r.get("target_date", ""), r.get("is_sample", 0),
            ),
        )
    conn.commit()
    log_action("SEED", details="Loaded 12 sample ransomware risk records")


# --------------------------------------------------------------------------- #
#  Helper: fetch single risk or 404                                             #
# --------------------------------------------------------------------------- #

def _get_risk_or_404(risk_id: str):
    conn = get_connection()
    try:
        risk = conn.execute(
            "SELECT * FROM risks WHERE risk_id = ?", (risk_id,)
        ).fetchone()
    finally:
        conn.close()
    if risk is None:
        abort(404)
    return risk


def _get_dashboard_stats() -> dict:
    conn = get_connection()
    try:
        rows = conn.execute("SELECT * FROM risks").fetchall()
    finally:
        conn.close()
    return build_report_summary(rows)


# --------------------------------------------------------------------------- #
#  Routes – Dashboard                                                           #
# --------------------------------------------------------------------------- #

@app.route("/")
def dashboard():
    stats = _get_dashboard_stats()
    conn = get_connection()
    try:
        recent_risks = conn.execute(
            "SELECT * FROM risks ORDER BY risk_score DESC LIMIT 5"
        ).fetchall()
        # Chart data: count by level
        level_counts = {
            "Critical": stats["critical"],
            "High": stats["high"],
            "Medium": stats["medium"],
            "Low": stats["low"],
        }
        # Chart data: count by NIST function
        func_counts = stats.get("by_nist_function", {})
    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_risks=recent_risks,
        level_counts=level_counts,
        func_counts=func_counts,
    )


# --------------------------------------------------------------------------- #
#  Routes – Risk Register                                                       #
# --------------------------------------------------------------------------- #

@app.route("/risks")
def risk_register():
    search = request.args.get("search", "").strip()
    filter_level = request.args.get("level", "").strip()
    filter_status = request.args.get("status", "").strip()
    filter_nist = request.args.get("nist_function", "").strip()

    conn = get_connection()
    try:
        query = "SELECT * FROM risks WHERE 1=1"
        params = []

        if search:
            query += " AND (title LIKE ? OR description LIKE ? OR risk_id LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like, like])

        if filter_level:
            query += " AND risk_level = ?"
            params.append(filter_level)

        if filter_status:
            query += " AND status = ?"
            params.append(filter_status)

        if filter_nist:
            query += " AND nist_function = ?"
            params.append(filter_nist)

        query += " ORDER BY risk_score DESC, created_at DESC"
        risks = conn.execute(query, params).fetchall()
    finally:
        conn.close()

    nist_func_list = get_functions_list()

    return render_template(
        "risk_register.html",
        risks=risks,
        search=search,
        filter_level=filter_level,
        filter_status=filter_status,
        filter_nist=filter_nist,
        nist_func_list=nist_func_list,
    )


# --------------------------------------------------------------------------- #
#  Routes – Add Risk                                                            #
# --------------------------------------------------------------------------- #

@app.route("/risks/add", methods=["GET", "POST"])
def add_risk():
    nist_func_list = get_functions_list()
    all_categories = get_all_categories()

    if request.method == "POST":
        form = request.form.to_dict()
        errors = validate_risk_form(form)

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template(
                "add_risk.html",
                form=form,
                nist_func_list=nist_func_list,
                all_categories=all_categories,
            )

        likelihood = int(form["likelihood"])
        impact = int(form["impact"])
        score = calculate_risk_score(likelihood, impact)
        level = classify_risk(score)

        # Generate next Risk ID
        conn = get_connection()
        try:
            max_id = conn.execute(
                "SELECT MAX(CAST(SUBSTR(risk_id, 5) AS INTEGER)) FROM risks WHERE risk_id LIKE 'RAN-%'"
            ).fetchone()[0]
            next_num = (max_id or 0) + 1
            new_risk_id = f"RAN-{next_num:03d}"

            conn.execute(
                """INSERT INTO risks
                   (risk_id, title, description, affected_asset, threat_source,
                    existing_controls, likelihood, impact, risk_score, risk_level,
                    nist_function, nist_category, nist_category_id, nist_explanation,
                    recommended_mitigation, risk_owner, status, target_date, is_sample)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (
                    new_risk_id,
                    form["title"].strip(),
                    form["description"].strip(),
                    form["affected_asset"].strip(),
                    form["threat_source"].strip(),
                    form.get("existing_controls", "").strip(),
                    likelihood, impact, score, level,
                    form["nist_function"].strip(),
                    form["nist_category"].strip(),
                    form["nist_category_id"].strip(),
                    form.get("nist_explanation", "").strip(),
                    form["recommended_mitigation"].strip(),
                    form["risk_owner"].strip(),
                    form["status"],
                    form.get("target_date", "").strip() or None,
                ),
            )
            conn.commit()
            log_action("CREATE", risk_id=new_risk_id, details=f"Created risk: {form['title']}")
        finally:
            conn.close()

        flash(f"Risk {new_risk_id} added successfully!", "success")
        return redirect(url_for("risk_detail", risk_id=new_risk_id))

    return render_template(
        "add_risk.html",
        form={},
        nist_func_list=nist_func_list,
        all_categories=all_categories,
    )


# --------------------------------------------------------------------------- #
#  Routes – Risk Detail                                                         #
# --------------------------------------------------------------------------- #

@app.route("/risks/<risk_id>")
def risk_detail(risk_id):
    risk = _get_risk_or_404(risk_id)
    return render_template("risk_detail.html", risk=risk)


# --------------------------------------------------------------------------- #
#  Routes – Edit Risk                                                           #
# --------------------------------------------------------------------------- #

@app.route("/risks/<risk_id>/edit", methods=["GET", "POST"])
def edit_risk(risk_id):
    risk = _get_risk_or_404(risk_id)
    nist_func_list = get_functions_list()
    all_categories = get_all_categories()

    if request.method == "POST":
        form = request.form.to_dict()
        errors = validate_risk_form(form)

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template(
                "edit_risk.html",
                risk=risk,
                form=form,
                nist_func_list=nist_func_list,
                all_categories=all_categories,
            )

        likelihood = int(form["likelihood"])
        impact = int(form["impact"])
        score = calculate_risk_score(likelihood, impact)
        level = classify_risk(score)

        conn = get_connection()
        try:
            conn.execute(
                """UPDATE risks SET
                   title=?, description=?, affected_asset=?, threat_source=?,
                   existing_controls=?, likelihood=?, impact=?, risk_score=?,
                   risk_level=?, nist_function=?, nist_category=?, nist_category_id=?,
                   nist_explanation=?, recommended_mitigation=?, risk_owner=?,
                   status=?, target_date=?
                   WHERE risk_id=?""",
                (
                    form["title"].strip(),
                    form["description"].strip(),
                    form["affected_asset"].strip(),
                    form["threat_source"].strip(),
                    form.get("existing_controls", "").strip(),
                    likelihood, impact, score, level,
                    form["nist_function"].strip(),
                    form["nist_category"].strip(),
                    form["nist_category_id"].strip(),
                    form.get("nist_explanation", "").strip(),
                    form["recommended_mitigation"].strip(),
                    form["risk_owner"].strip(),
                    form["status"],
                    form.get("target_date", "").strip() or None,
                    risk_id,
                ),
            )
            conn.commit()
            log_action("UPDATE", risk_id=risk_id, details=f"Updated risk: {form['title']}")
        finally:
            conn.close()

        flash(f"Risk {risk_id} updated successfully!", "success")
        return redirect(url_for("risk_detail", risk_id=risk_id))

    # GET – pre-fill form from existing record
    form = dict(risk)
    return render_template(
        "edit_risk.html",
        risk=risk,
        form=form,
        nist_func_list=nist_func_list,
        all_categories=all_categories,
    )


# --------------------------------------------------------------------------- #
#  Routes – Delete Risk                                                         #
# --------------------------------------------------------------------------- #

@app.route("/risks/<risk_id>/delete", methods=["POST"])
def delete_risk(risk_id):
    risk = _get_risk_or_404(risk_id)
    conn = get_connection()
    try:
        conn.execute("DELETE FROM risks WHERE risk_id = ?", (risk_id,))
        conn.commit()
        log_action("DELETE", risk_id=risk_id, details=f"Deleted risk: {dict(risk)['title']}")
    finally:
        conn.close()
    flash(f"Risk {risk_id} deleted.", "info")
    return redirect(url_for("risk_register"))


# --------------------------------------------------------------------------- #
#  Routes – Update Status (AJAX / quick action)                                 #
# --------------------------------------------------------------------------- #

@app.route("/risks/<risk_id>/status", methods=["POST"])
def update_status(risk_id):
    _get_risk_or_404(risk_id)
    new_status = request.form.get("status", "").strip()
    valid = {"Open", "In Progress", "Mitigated", "Accepted", "Closed"}
    if new_status not in valid:
        flash("Invalid status value.", "danger")
        return redirect(url_for("risk_detail", risk_id=risk_id))

    conn = get_connection()
    try:
        conn.execute(
            "UPDATE risks SET status=? WHERE risk_id=?", (new_status, risk_id)
        )
        conn.commit()
        log_action("STATUS_UPDATE", risk_id=risk_id, details=f"Status changed to {new_status}")
    finally:
        conn.close()
    flash(f"Status updated to '{new_status}'.", "success")
    return redirect(url_for("risk_detail", risk_id=risk_id))


# --------------------------------------------------------------------------- #
#  Routes – NIST Mapping Page                                                   #
# --------------------------------------------------------------------------- #

@app.route("/nist-mapping")
def nist_mapping():
    conn = get_connection()
    try:
        risks = conn.execute(
            "SELECT * FROM risks ORDER BY nist_function, nist_category_id"
        ).fetchall()
    finally:
        conn.close()

    functions_list = get_functions_list()
    categories_by_func = get_categories_by_function()

    return render_template(
        "nist_mapping.html",
        risks=risks,
        functions_list=functions_list,
        categories_by_func=categories_by_func,
    )


# --------------------------------------------------------------------------- #
#  Routes – Reports                                                             #
# --------------------------------------------------------------------------- #

@app.route("/reports")
def reports():
    conn = get_connection()
    try:
        risks = conn.execute(
            "SELECT * FROM risks ORDER BY risk_score DESC"
        ).fetchall()
    finally:
        conn.close()

    summary = build_report_summary(risks)
    return render_template("reports.html", risks=risks, summary=summary)


@app.route("/reports/export/csv")
def export_csv():
    conn = get_connection()
    try:
        risks = conn.execute(
            "SELECT * FROM risks ORDER BY risk_score DESC"
        ).fetchall()
    finally:
        conn.close()

    csv_data = risks_to_csv(risks)
    response = make_response(csv_data)
    response.headers["Content-Disposition"] = (
        "attachment; filename=ransomware_risk_register.csv"
    )
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response


# --------------------------------------------------------------------------- #
#  Routes – API (JSON) for chart refresh                                        #
# --------------------------------------------------------------------------- #

@app.route("/api/stats")
def api_stats():
    stats = _get_dashboard_stats()
    return jsonify(stats)


@app.route("/api/risks")
def api_risks():
    conn = get_connection()
    try:
        risks = conn.execute("SELECT * FROM risks ORDER BY risk_score DESC").fetchall()
        data = [dict(r) for r in risks]
    finally:
        conn.close()
    return jsonify(data)


# --------------------------------------------------------------------------- #
#  Routes – About                                                               #
# --------------------------------------------------------------------------- #

@app.route("/about")
def about():
    return render_template("about.html")


# --------------------------------------------------------------------------- #
#  Error Handlers                                                               #
# --------------------------------------------------------------------------- #

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500


# --------------------------------------------------------------------------- #
#  Entry Point                                                                  #
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    bootstrap_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
