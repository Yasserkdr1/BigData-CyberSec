from flask import Flask, jsonify, render_template_string
from cassandra.cluster import Cluster
from datetime import datetime

app = Flask(__name__)

CASSANDRA_HOST = "127.0.0.1"
CASSANDRA_PORT = 9042
CASSANDRA_KEYSPACE = "cybersec"
cluster = Cluster([CASSANDRA_HOST], port=CASSANDRA_PORT)
session = cluster.connect(CASSANDRA_KEYSPACE)

prepared_alerts = session.prepare("""
    SELECT alert_date, inserted_at, event_time, alert_type, source_ip, request_path, count_value
    FROM realtime_alerts_live
    WHERE alert_date = ?
    LIMIT 200
""")

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSec Live Dashboard</title>
    <style>
        * { box-sizing: border-box; }

        body {
            margin: 0;
            padding: 24px;
            font-family: Inter, Arial, sans-serif;
            background:
                radial-gradient(circle at top left, rgba(255,70,70,0.10), transparent 30%),
                radial-gradient(circle at top right, rgba(0,170,255,0.08), transparent 25%),
                #0b1020;
            color: #eaf1ff;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }

        .title-block h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 800;
            letter-spacing: 0.5px;
        }

        .title-block p {
            margin: 8px 0 0;
            color: #9fb0d3;
            font-size: 14px;
        }

        .stats {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }

        .card {
            background: rgba(17, 24, 39, 0.85);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 16px;
            padding: 14px 16px;
            min-width: 160px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.25);
            backdrop-filter: blur(8px);
        }

        .card .label {
            font-size: 12px;
            color: #8aa0c8;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }

        .card .value {
            font-size: 22px;
            font-weight: 700;
        }

        .panel {
            background: rgba(17, 24, 39, 0.88);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 20px;
            padding: 16px;
            box-shadow: 0 18px 40px rgba(0,0,0,0.35);
            backdrop-filter: blur(10px);
        }

        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
            flex-wrap: wrap;
        }

        .toolbar-left {
            display: flex;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
        }

        .toolbar-right {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #19c37d;
            box-shadow: 0 0 12px #19c37d;
        }

        .toolbar-text {
            color: #aab8d4;
            font-size: 14px;
        }

        .btn {
            border: none;
            border-radius: 12px;
            padding: 10px 14px;
            background: #18233b;
            color: #eaf1ff;
            cursor: pointer;
            font-weight: 600;
        }

        .btn:hover {
            background: #22304d;
        }

        .btn:disabled {
            opacity: 0.45;
            cursor: not-allowed;
        }

        .table-wrapper {
            max-height: 560px;
            overflow-y: auto;
            border-radius: 14px;
            border: 1px solid rgba(255,255,255,0.06);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 900px;
        }

        thead th {
            position: sticky;
            top: 0;
            z-index: 2;
            background: #121a2d;
            color: #ffcf66;
            text-align: left;
            padding: 14px;
            font-size: 13px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }

        tbody td {
            padding: 14px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            font-size: 14px;
            color: #e5ecfb;
        }

        tbody tr:hover {
            background: rgba(255,255,255,0.04);
        }

        .badge {
            display: inline-block;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.03em;
        }

        .badge.SQLMAP, .badge.SQLI_TAUTOLOGY, .badge.SQLI_UNION,
        .badge.SQLI_INFO_SCHEMA, .badge.SQLI_TIME_BASED, .badge.SQLI_BENCHMARK,
        .badge.SQLI_XP_CMDSHELL {
            background: rgba(255, 99, 132, 0.18);
            color: #ff7d96;
        }

        .badge.NMAP, .badge.NIKTO, .badge.MASSCAN, .badge.NESSUS, .badge.WPSCAN {
            background: rgba(255, 159, 64, 0.18);
            color: #ffb15c;
        }

        .badge.BRUTE_FORCE, .badge.ADMIN_ACCESS, .badge.WP_LOGIN {
            background: rgba(255, 206, 86, 0.18);
            color: #ffd86c;
        }

        .badge.DATA_EXFILTRATION {
            background: rgba(54, 162, 235, 0.18);
            color: #6fc5ff;
        }

        .badge.default {
            background: rgba(153, 102, 255, 0.18);
            color: #b99cff;
        }

        .muted {
            color: #8fa4cb;
        }

        .pagination {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-top: 14px;
            flex-wrap: wrap;
        }

        .page-info {
            color: #9fb0d3;
            font-size: 14px;
        }

        .empty {
            text-align: center;
            padding: 30px;
            color: #8fa4cb;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title-block">
                <h1>🚨 CyberSec Live Dashboard</h1>
                <p>Menaces détectées et stockées dans Cassandra, triées des plus récentes aux plus anciennes.</p>
            </div>

            <div class="stats">
                <div class="card">
                    <div class="label">Total chargé</div>
                    <div class="value" id="total-count">0</div>
                </div>
                <div class="card">
                    <div class="label">Page actuelle</div>
                    <div class="value" id="page-number">1</div>
                </div>
                <div class="card">
                    <div class="label">Dernière MAJ</div>
                    <div class="value" id="last-refresh" style="font-size:16px;">--:--:--</div>
                </div>
            </div>
        </div>

        <div class="panel">
            <div class="toolbar">
                <div class="toolbar-left">
                    <div class="status-dot"></div>
                    <div class="toolbar-text">Flux actif</div>
                    <div class="toolbar-text" id="page-summary">Chargement...</div>
                </div>

                <div class="toolbar-right">
                    <button class="btn" id="prev-btn">← Précédent</button>
                    <button class="btn" id="next-btn">Suivant →</button>
                </div>
            </div>

            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>
                            <th>Heure Détection</th>
                            <th>Type d'Alerte</th>
                            <th>IP Source</th>
                            <th>Cible / Chemin</th>
                            <th>Détails</th>
                        </tr>
                    </thead>
                    <tbody id="alerts-table-body">
                        <tr><td colspan="5" class="empty">Chargement des alertes...</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="pagination">
                <div class="page-info" id="pagination-info">Page 1</div>
                <div class="page-info">20 lignes par page</div>
            </div>
        </div>
    </div>

    <script>
        let allAlerts = [];
        let currentPage = 1;
        const rowsPerPage = 20;

        function badgeClass(type) {
            if (!type) return "default";
            return type;
        }

        function renderTable() {
            const tbody = document.getElementById("alerts-table-body");
            const total = allAlerts.length;
            const totalPages = Math.max(1, Math.ceil(total / rowsPerPage));

            if (currentPage > totalPages) currentPage = totalPages;

            const start = (currentPage - 1) * rowsPerPage;
            const end = start + rowsPerPage;
            const pageData = allAlerts.slice(start, end);

            if (pageData.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" class="empty">Aucune alerte disponible.</td></tr>`;
            } else {
                tbody.innerHTML = pageData.map(alert => `
                    <tr>
                        <td>${alert.display_time || "N/A"}</td>
                        <td><span class="badge ${badgeClass(alert.alert_type)}">${alert.alert_type}</span></td>
                        <td>${alert.src_ip || "-"}</td>
                        <td>${alert.path || "-"}</td>
                        <td>${alert.count_value !== null && alert.count_value !== undefined ? alert.count_value : "-"}</td>
                    </tr>
                `).join("");
            }

            document.getElementById("total-count").textContent = total;
            document.getElementById("page-number").textContent = currentPage;
            document.getElementById("pagination-info").textContent = `Page ${currentPage} / ${totalPages}`;
            document.getElementById("page-summary").textContent = `${total} alertes récupérées`;
            document.getElementById("prev-btn").disabled = currentPage === 1;
            document.getElementById("next-btn").disabled = currentPage === totalPages;
        }

        async function fetchAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const alerts = await response.json();

                if (!Array.isArray(alerts)) {
                    return;
                }

                allAlerts = alerts;
                renderTable();

                const now = new Date();
                document.getElementById("last-refresh").textContent = now.toLocaleTimeString("fr-FR");
            } catch (error) {
                console.error("Erreur API:", error);
            }
        }

        document.getElementById("prev-btn").addEventListener("click", () => {
            if (currentPage > 1) {
                currentPage--;
                renderTable();
            }
        });

        document.getElementById("next-btn").addEventListener("click", () => {
            const totalPages = Math.max(1, Math.ceil(allAlerts.length / rowsPerPage));
            if (currentPage < totalPages) {
                currentPage++;
                renderTable();
            }
        });

        fetchAlerts();
        setInterval(fetchAlerts, 1000);
    </script>
</body>
</html>
"""

@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route("/api/alerts")
def get_alerts():
    try:
        today = datetime.utcnow().date()
        rows = session.execute(prepared_alerts, [today])

        alerts_list = []
        for r in rows:
            raw_time = r.inserted_at if r.inserted_at else r.event_time

            alerts_list.append({
                "display_time": raw_time.strftime("%H:%M:%S") if raw_time else "N/A",
                "alert_type": r.alert_type,
                "src_ip": r.source_ip,
                "path": r.request_path,
                "count_value": r.count_value
            })

        return jsonify(alerts_list)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)