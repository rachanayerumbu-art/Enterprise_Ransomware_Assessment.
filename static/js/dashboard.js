/**
 * static/js/dashboard.js
 * Dashboard stats auto-refresh (every 60 seconds)
 * Optional progressive enhancement — charts are rendered inline in dashboard.html
 */

"use strict";

(function () {
    // Refresh dashboard stat cards by polling the /api/stats endpoint
    function refreshStats() {
        fetch("/api/stats")
            .then(res => res.json())
            .then(data => {
                // Update only the numeric cells by data-stat attribute
                document.querySelectorAll("[data-stat]").forEach(el => {
                    const key = el.getAttribute("data-stat");
                    if (key in data) el.textContent = data[key];
                });
            })
            .catch(() => {
                // Silently ignore fetch errors (offline / server restarting)
            });
    }

    // Poll every 60 seconds
    setInterval(refreshStats, 60000);
})();
