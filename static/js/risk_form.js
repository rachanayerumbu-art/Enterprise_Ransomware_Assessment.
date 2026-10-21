/**
 * static/js/risk_form.js
 * Client-side scoring calculator and NIST category filter
 * for the Add Risk and Edit Risk forms.
 */

"use strict";

// ── Risk Level Classification (mirrors risk_engine.py) ──────────────────────
function classifyRisk(score) {
    if (score <= 0)  return { level: "—",        cls: "" };
    if (score <= 4)  return { level: "Low",       cls: "badge-low" };
    if (score <= 9)  return { level: "Medium",    cls: "badge-medium" };
    if (score <= 16) return { level: "High",      cls: "badge-high" };
    return               { level: "Critical",  cls: "badge-critical" };
}

// ── Score Calculator ─────────────────────────────────────────────────────────
function calcScore() {
    const lSel = document.getElementById("likelihoodSel");
    const iSel = document.getElementById("impactSel");
    const scoreEl = document.getElementById("scoreDisplay");
    const levelEl = document.getElementById("levelDisplay");

    if (!lSel || !iSel || !scoreEl || !levelEl) return;

    const l = parseInt(lSel.value, 10);
    const i = parseInt(iSel.value, 10);

    if (isNaN(l) || isNaN(i)) {
        scoreEl.textContent = "–";
        scoreEl.style.color = "";
        levelEl.innerHTML = "";
        return;
    }

    const score = l * i;
    const { level, cls } = classifyRisk(score);

    scoreEl.textContent = score;

    // Colour the score number by level
    const colorMap = {
        "Critical": "#ef4444",
        "High":     "#f97316",
        "Medium":   "#eab308",
        "Low":      "#22c55e",
    };
    scoreEl.style.color = colorMap[level] || "";

    levelEl.innerHTML = level !== "—"
        ? `<span class="badge ${cls} badge-lg">${level} Risk</span>`
        : "";
}

// ── NIST Category Filter ─────────────────────────────────────────────────────
function filterCategories() {
    const fnSel  = document.getElementById("nistFunctionSel");
    const catSel = document.getElementById("nistCatSel");
    if (!fnSel || !catSel) return;

    const selectedFunction = fnSel.value;  // e.g. "Protect"

    // Map function names to two-letter codes
    const codeMap = {
        Govern: "GV", Identify: "ID", Protect: "PR",
        Detect: "DE", Respond: "RS", Recover: "RC",
    };
    const code = codeMap[selectedFunction] || selectedFunction.slice(0, 2).toUpperCase();

    Array.from(catSel.options).forEach(opt => {
        if (!opt.value) return;  // keep the placeholder
        const optFunc = opt.getAttribute("data-function") || "";
        opt.hidden = selectedFunction !== "" && optFunc !== code;
    });

    // If currently selected option is now hidden, reset
    const selectedOpt = catSel.options[catSel.selectedIndex];
    if (selectedOpt && selectedOpt.hidden) {
        catSel.value = "";
        fillCategoryName();
    }
}

// ── Fill hidden nist_category name field ─────────────────────────────────────
function fillCategoryName() {
    const catSel = document.getElementById("nistCatSel");
    const hidden = document.getElementById("nistCategoryHidden");
    if (!catSel || !hidden) return;

    const selected = catSel.options[catSel.selectedIndex];
    hidden.value = selected ? (selected.getAttribute("data-name") || "") : "";
}

// ── Form Validation (client-side pre-check) ──────────────────────────────────
document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("riskForm");
    if (!form) return;

    form.addEventListener("submit", function (e) {
        const errors = [];

        const requiredTextIds = [
            "title", "affected_asset", "description",
            "threat_source", "recommended_mitigation", "risk_owner",
        ];
        requiredTextIds.forEach(name => {
            const el = form.querySelector(`[name="${name}"]`);
            if (el && !el.value.trim()) {
                errors.push(`"${el.previousElementSibling?.textContent || name}" is required.`);
            }
        });

        const lSel = document.getElementById("likelihoodSel");
        const iSel = document.getElementById("impactSel");
        if (lSel && !lSel.value) errors.push("Likelihood is required.");
        if (iSel && !iSel.value) errors.push("Impact is required.");

        const fnSel  = document.getElementById("nistFunctionSel");
        const catSel = document.getElementById("nistCatSel");
        if (fnSel  && !fnSel.value)  errors.push("NIST Function is required.");
        if (catSel && !catSel.value) errors.push("NIST Category is required.");

        if (errors.length > 0) {
            e.preventDefault();
            alert("Please fix the following errors:\n\n" + errors.join("\n"));
        } else {
            // Ensure the hidden category name is populated before submit
            fillCategoryName();
        }
    });
});
