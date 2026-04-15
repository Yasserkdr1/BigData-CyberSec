from flask import Flask, jsonify, render_template_string
from cassandra.cluster import Cluster
from datetime import datetime
import happybase

app = Flask(__name__)

# -----------------------------
# Cassandra (Speed Layer)
# -----------------------------
CASSANDRA_HOST = "127.0.0.1"
CASSANDRA_PORT = 9042
CASSANDRA_KEYSPACE = "cybersec"

cluster = Cluster([CASSANDRA_HOST], port=CASSANDRA_PORT)
session = cluster.connect(CASSANDRA_KEYSPACE)

prepared_alerts = session.prepare("""
    SELECT alert_date, inserted_at, event_time, alert_type, source_ip, request_path, count_value, protocol, user_agent, dest_ip
    FROM realtime_alerts_live
    WHERE alert_date = ?
    LIMIT 200
""")

# -----------------------------
# HBase (Batch Layer)
# -----------------------------
HBASE_HOST = "127.0.0.1"
HBASE_PORT = 9090


def get_hbase_connection():
    connection = happybase.Connection(HBASE_HOST, port=HBASE_PORT)
    connection.open()
    return connection


def scan_table_as_dict(table_name):
    conn = get_hbase_connection()
    table = conn.table(table_name)

    rows = []
    for key, data in table.scan():
        row_key = key.decode() if isinstance(key, bytes) else str(key)
        decoded = {}
        for k, v in data.items():
            col_name = k.decode() if isinstance(k, bytes) else str(k)
            value = v.decode() if isinstance(v, bytes) else str(v)
            decoded[col_name] = value
        rows.append({"key": row_key, **decoded})

    conn.close()
    return rows


def normalize_hbase_rows(rows):
    result = []
    for r in rows:
        val = r.get("cf:alert_count", "0")
        try:
            val = int(val)
        except Exception:
            val = 0
        result.append({"name": r["key"], "value": val})
    result.sort(key=lambda x: x["value"], reverse=True)
    return result


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSec Lambda Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { box-sizing: border-box; }

        body {
            margin: 0;
            padding: 0;
            font-family: Inter, Arial, sans-serif;
            background:
                radial-gradient(circle at top left, rgba(255,70,70,0.08), transparent 35%),
                radial-gradient(circle at top right, rgba(0,170,255,0.08), transparent 35%),
                #0b1020;
            color: #eaf1ff;
            display: flex;
            min-height: 100vh;
        }

        .sidebar {
            width: 260px;
            background: rgba(17, 24, 39, 0.95);
            border-right: 1px solid rgba(255,255,255,0.08);
            padding: 24px 16px;
            display: flex;
            flex-direction: column;
            gap: 28px;
        }

        .brand h1 {
            margin: 0;
            font-size: 22px;
            font-weight: 800;
            color: #fff;
        }

        .brand p {
            margin: 6px 0 0;
            color: #8aa0c8;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .nav-menu {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .nav-btn {
            background: transparent;
            border: none;
            color: #8aa0c8;
            padding: 14px 16px;
            border-radius: 12px;
            text-align: left;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.2s ease;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .nav-btn:hover {
            background: rgba(255,255,255,0.05);
            color: #fff;
        }

        .nav-btn.active {
            background: rgba(25, 195, 125, 0.15);
            color: #19c37d;
            border: 1px solid rgba(25, 195, 125, 0.25);
        }

        .nav-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: transparent;
        }

        .nav-btn.active .nav-indicator {
            background: #19c37d;
            box-shadow: 0 0 10px #19c37d;
        }

        .main-wrapper {
            flex: 1;
            padding: 28px 36px;
            overflow-y: auto;
        }

        .view-section { display: none; }
        .view-section.active { display: block; }

        .view-header {
            display: flex;
            justify-content: space-between;
            align-items: end;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }

        .view-title h2 {
            margin: 0;
            font-size: 26px;
            font-weight: 800;
        }

        .view-title p {
            margin: 6px 0 0;
            color: #8aa0c8;
            font-size: 14px;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 18px;
        }

        .card, .panel {
            background: rgba(17, 24, 39, 0.82);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 18px;
            padding: 18px;
            backdrop-filter: blur(8px);
            box-shadow: 0 12px 35px rgba(0,0,0,0.25);
        }

        .span-3 { grid-column: span 3; }
        .span-6 { grid-column: span 6; }
        .span-12 { grid-column: span 12; }

        .kpi-label {
            font-size: 12px;
            color: #8aa0c8;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .kpi-value {
            font-size: 34px;
            font-weight: 800;
            margin-top: 10px;
            color: #fff;
        }

        .section-title {
            margin: 0;
            color: #9fb0d3;
            font-size: 15px;
            font-weight: 700;
        }

        .chart-container {
            position: relative;
            height: 280px;
            width: 100%;
            margin-top: 14px;
            background: rgba(255,255,255,0.02);
            border: 1px solid rgba(255,255,255,0.05);
            border-radius: 14px;
            padding: 10px;
        }

        .table-wrapper {
            max-height: 520px;
            overflow-y: auto;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.05);
            margin-top: 14px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            min-width: 980px;
        }

        thead th {
            position: sticky;
            top: 0;
            background: #121a2d;
            color: #ffcf66;
            text-align: left;
            padding: 14px;
            font-size: 13px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
        }

        tbody td {
            padding: 14px;
            border-bottom: 1px solid rgba(255,255,255,0.04);
            font-size: 14px;
            color: #e5ecfb;
        }

        tbody tr:hover {
            background: rgba(255,255,255,0.03);
        }

        .empty {
            text-align: center;
            padding: 34px;
            color: #8fa4cb;
        }

        .badge {
            display: inline-block;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
        }

        .badge.default {
            background: rgba(153,102,255,0.16);
            color: #c4a8ff;
        }

        .badge.sql {
            background: rgba(255,99,132,0.16);
            color: #ff8ea3;
        }

        .badge.scan {
            background: rgba(255,159,64,0.16);
            color: #ffbc7b;
        }

        .badge.brute {
            background: rgba(255,206,86,0.16);
            color: #ffe08a;
        }

        .badge.exfil {
            background: rgba(54,162,235,0.16);
            color: #7fd1ff;
        }

        .list-box {
            margin-top: 14px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }

        .list-row {
            display: flex;
            justify-content: space-between;
            padding: 12px 14px;
            border-radius: 12px;
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.04);
        }

        .list-row .name {
            color: #dfe7fb;
            font-weight: 600;
        }

        .list-row .value {
            color: #7ee081;
            font-weight: 800;
        }

        @media (max-width: 1200px) {
            .span-3, .span-6, .span-12 { grid-column: span 12; }
            .sidebar { width: 220px; }
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="brand">
            <h1>🚨 CyberSec SOC</h1>
            <p>Lambda Architecture</p>
        </div>

        <div class="nav-menu">
            <button class="nav-btn active" onclick="switchView('streaming-view', this)">
                ⚡ Temps Réel
                <div class="nav-indicator"></div>
            </button>
            <button class="nav-btn" onclick="switchView('batch-view', this)">
                📚 Batch & Analytics
                <div class="nav-indicator"></div>
            </button>
        </div>
    </div>

    <div class="main-wrapper">

        <div id="streaming-view" class="view-section active">
            <div class="view-header">
                <div class="view-title">
                    <h2>Flux d'Alertes Temps Réel</h2>
                    <p>Cassandra + Spark Streaming</p>
                </div>
                <div style="color:#19c37d;font-size:13px;font-weight:700;" id="last-refresh-live">MAJ: --:--:--</div>
            </div>

            <div class="dashboard-grid">
                <div class="card span-3">
                    <div class="kpi-label">Menaces actives</div>
                    <div class="kpi-value" id="kpi-live-total">0</div>
                </div>

                <div class="card span-3">
                    <div class="kpi-label">Types d'alertes</div>
                    <div class="kpi-value" id="kpi-live-types">0</div>
                </div>

                <div class="card span-3">
                    <div class="kpi-label">IPs sources</div>
                    <div class="kpi-value" id="kpi-live-ips">0</div>
                </div>

                <div class="card span-3">
                    <div class="kpi-label">Dernière détection</div>
                    <div class="kpi-value" id="kpi-live-last" style="font-size:24px;">--:--:--</div>
                </div>

                <div class="panel span-12">
                    <h3 class="section-title">Journal des incidents live</h3>
                    <div class="table-wrapper">
                        <table>
                            <thead>
                                <tr>
                                    <th>Heure</th>
                                    <th>Alerte</th>
                                    <th>IP source</th>
                                    <th>IP destination</th>
                                    <th>Protocole</th>
                                    <th>Chemin / cible</th>
                                    <th>Détail</th>
                                </tr>
                            </thead>
                            <tbody id="alerts-table-body">
                                <tr><td colspan="7" class="empty">Chargement des alertes live...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <div id="batch-view" class="view-section">
            <div class="view-header">
                <div class="view-title">
                    <h2>Vue Batch : Récent + Global</h2>
                    <p>HBase + Spark Batch</p>
                </div>
                <div style="color:#00aaff;font-size:13px;font-weight:700;" id="last-refresh-batch">MAJ: --:--:--</div>
            </div>

            <div class="dashboard-grid">
                <div class="card span-3">
                    <div class="kpi-label">IPs récentes</div>
                    <div class="kpi-value" id="kpi-recent-ip">0</div>
                </div>

                <div class="card span-3">
                    <div class="kpi-label">Protocoles récents</div>
                    <div class="kpi-value" id="kpi-recent-protocol">0</div>
                </div>

                <div class="card span-3">
                    <div class="kpi-label">Patterns récents</div>
                    <div class="kpi-value" id="kpi-recent-pattern">0</div>
                </div>

                <div class="card span-3">
                    <div class="kpi-label">Patterns globaux</div>
                    <div class="kpi-value" id="kpi-global-pattern">0</div>
                </div>

                <div class="panel span-6">
                    <h3 class="section-title">Top protocoles récents</h3>
                    <div class="chart-container">
                        <canvas id="recentProtocolsChart"></canvas>
                    </div>
                </div>

                <div class="panel span-6">
                    <h3 class="section-title">Top patterns récents</h3>
                    <div class="chart-container">
                        <canvas id="recentPatternsChart"></canvas>
                    </div>
                </div>

                <div class="panel span-6">
                    <h3 class="section-title">Top protocoles globaux</h3>
                    <div class="chart-container">
                        <canvas id="globalProtocolsChart"></canvas>
                    </div>
                </div>

                <div class="panel span-6">
                    <h3 class="section-title">Top patterns globaux</h3>
                    <div class="chart-container">
                        <canvas id="globalPatternsChart"></canvas>
                    </div>
                </div>

                <div class="panel span-6">
                    <h3 class="section-title">Top IPs récentes</h3>
                    <div class="list-box" id="recent-ip-list"></div>
                </div>

                <div class="panel span-6">
                    <h3 class="section-title">Top IPs globales</h3>
                    <div class="list-box" id="global-ip-list"></div>
                </div>
            </div>
        </div>

    </div>

    <script>
        Chart.defaults.color = '#d7e3ff';
        Chart.defaults.borderColor = 'rgba(255,255,255,0.08)';
        Chart.defaults.font.family = 'Inter, Arial, sans-serif';

        const CHART_COLORS = [
            '#00c2ff',
            '#19c37d',
            '#ffb020',
            '#ff5d73',
            '#a78bfa',
            '#4dd4ac',
            '#7cc8ff',
            '#ffd166',
            '#ff8fab',
            '#7ee081'
        ];

        function buildColors(count) {
            const arr = [];
            for (let i = 0; i < count; i++) {
                arr.push(CHART_COLORS[i % CHART_COLORS.length]);
            }
            return arr;
        }

        function switchView(viewId, btnElement) {
            document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById(viewId).classList.add('active');
            btnElement.classList.add('active');
        }

        function alertBadgeClass(type) {
            const t = (type || '').toUpperCase();
            if (t.includes('SQL') || t.includes('XSS') || t.includes('CMD')) return 'sql';
            if (t.includes('NMAP') || t.includes('NIKTO') || t.includes('SCAN')) return 'scan';
            if (t.includes('BLOCKED') || t.includes('LOGIN') || t.includes('BRUTE')) return 'brute';
            if (t.includes('EXFIL')) return 'exfil';
            return 'default';
        }

        let recentProtocolsChart, recentPatternsChart, globalProtocolsChart, globalPatternsChart;

        function makeDoughnut(canvasId, labels, values) {
            const ctx = document.getElementById(canvasId).getContext('2d');
            const colors = buildColors(labels.length);

            return new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: colors,
                        borderColor: 'rgba(255,255,255,0.18)',
                        borderWidth: 2,
                        hoverOffset: 8
                    }]
                },
                options: {
                    maintainAspectRatio: false,
                    cutout: '62%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                color: '#e8f0ff',
                                padding: 18,
                                usePointStyle: true,
                                pointStyle: 'circle'
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(15, 23, 42, 0.96)',
                            titleColor: '#ffffff',
                            bodyColor: '#dbeafe',
                            borderColor: 'rgba(255,255,255,0.12)',
                            borderWidth: 1
                        }
                    }
                }
            });
        }

        function makeBar(canvasId, labels, values) {
            const ctx = document.getElementById(canvasId).getContext('2d');
            const colors = buildColors(labels.length);

            return new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        data: values,
                        backgroundColor: colors,
                        borderColor: 'rgba(255,255,255,0.18)',
                        borderWidth: 1.5,
                        borderRadius: 8
                    }]
                },
                options: {
                    indexAxis: 'y',
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(15, 23, 42, 0.96)',
                            titleColor: '#ffffff',
                            bodyColor: '#dbeafe',
                            borderColor: 'rgba(255,255,255,0.12)',
                            borderWidth: 1
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: '#d7e3ff' },
                            grid: { color: 'rgba(255,255,255,0.06)' }
                        },
                        y: {
                            ticks: { color: '#e8f0ff' },
                            grid: { color: 'rgba(255,255,255,0.03)' }
                        }
                    }
                }
            });
        }

        function updateOrCreateChart(chartRef, type, canvasId, labels, values) {
            if (chartRef) chartRef.destroy();
            if (type === 'doughnut') return makeDoughnut(canvasId, labels, values);
            return makeBar(canvasId, labels, values);
        }

        function fillList(containerId, rows) {
            const container = document.getElementById(containerId);
            if (!rows.length) {
                container.innerHTML = '<div class="empty">Aucune donnée</div>';
                return;
            }
            container.innerHTML = rows.map(r => `
                <div class="list-row">
                    <div class="name">${r.name}</div>
                    <div class="value">${r.value}</div>
                </div>
            `).join('');
        }

        async function fetchLiveAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const alerts = await response.json();
                if (!Array.isArray(alerts)) return;

                document.getElementById('kpi-live-total').textContent = alerts.length;
                document.getElementById('kpi-live-types').textContent = new Set(alerts.map(a => a.alert_type)).size;
                document.getElementById('kpi-live-ips').textContent = new Set(alerts.map(a => a.src_ip)).size;
                document.getElementById('kpi-live-last').textContent = alerts.length ? alerts[0].display_time : '--:--:--';

                const tbody = document.getElementById('alerts-table-body');
                const displayAlerts = alerts.slice(0, 60);

                if (!displayAlerts.length) {
                    tbody.innerHTML = '<tr><td colspan="7" class="empty">Aucune alerte active détectée.</td></tr>';
                } else {
                    tbody.innerHTML = displayAlerts.map(alert => `
                        <tr>
                            <td>${alert.display_time || 'N/A'}</td>
                            <td><span class="badge ${alertBadgeClass(alert.alert_type)}">${alert.alert_type}</span></td>
                            <td>${alert.src_ip || '-'}</td>
                            <td>${alert.dest_ip || '-'}</td>
                            <td>${alert.protocol || '-'}</td>
                            <td>${alert.path || '-'}</td>
                            <td>${alert.count_value !== null && alert.count_value !== undefined ? alert.count_value : '-'}</td>
                        </tr>
                    `).join('');
                }

                document.getElementById('last-refresh-live').textContent = 'MAJ: ' + new Date().toLocaleTimeString('fr-FR');
            } catch (e) {
                console.error('Live alerts error:', e);
            }
        }

        async function fetchBatchStats() {
            try {
                const [recentResp, globalResp] = await Promise.all([
                    fetch('/api/batch/recent'),
                    fetch('/api/batch/global')
                ]);

                const recent = await recentResp.json();
                const global = await globalResp.json();

                document.getElementById('kpi-recent-ip').textContent = recent.ip_stats.length;
                document.getElementById('kpi-recent-protocol').textContent = recent.protocol_stats.length;
                document.getElementById('kpi-recent-pattern').textContent = recent.attack_patterns.length;
                document.getElementById('kpi-global-pattern').textContent = global.attack_patterns.length;

                recentProtocolsChart = updateOrCreateChart(
                    recentProtocolsChart,
                    'doughnut',
                    'recentProtocolsChart',
                    recent.protocol_stats.map(x => x.name),
                    recent.protocol_stats.map(x => x.value)
                );

                recentPatternsChart = updateOrCreateChart(
                    recentPatternsChart,
                    'bar',
                    'recentPatternsChart',
                    recent.attack_patterns.map(x => x.name),
                    recent.attack_patterns.map(x => x.value)
                );

                globalProtocolsChart = updateOrCreateChart(
                    globalProtocolsChart,
                    'doughnut',
                    'globalProtocolsChart',
                    global.protocol_stats.map(x => x.name),
                    global.protocol_stats.map(x => x.value)
                );

                globalPatternsChart = updateOrCreateChart(
                    globalPatternsChart,
                    'bar',
                    'globalPatternsChart',
                    global.attack_patterns.map(x => x.name),
                    global.attack_patterns.map(x => x.value)
                );

                fillList('recent-ip-list', recent.ip_stats.slice(0, 8));
                fillList('global-ip-list', global.ip_stats.slice(0, 8));

                document.getElementById('last-refresh-batch').textContent = 'MAJ: ' + new Date().toLocaleTimeString('fr-FR');
            } catch (e) {
                console.error('Batch stats error:', e);
            }
        }

        fetchLiveAlerts();
        fetchBatchStats();

        setInterval(fetchLiveAlerts, 2000);
        setInterval(fetchBatchStats, 10000);
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
                "dest_ip": r.dest_ip,
                "protocol": r.protocol,
                "path": r.request_path,
                "count_value": r.count_value
            })

        alerts_list.sort(key=lambda x: x["display_time"], reverse=True)
        return jsonify(alerts_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/batch/recent")
def get_recent_batch_stats():
    try:
        recent_ip = normalize_hbase_rows(scan_table_as_dict("recent_ip_stats"))
        recent_protocol = normalize_hbase_rows(scan_table_as_dict("recent_protocol_stats"))
        recent_patterns = normalize_hbase_rows(scan_table_as_dict("recent_attack_patterns"))

        return jsonify({
            "ip_stats": recent_ip,
            "protocol_stats": recent_protocol,
            "attack_patterns": recent_patterns
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/batch/global")
def get_global_batch_stats():
    try:
        global_ip = normalize_hbase_rows(scan_table_as_dict("global_ip_stats"))
        global_protocol = normalize_hbase_rows(scan_table_as_dict("global_protocol_stats"))
        global_patterns = normalize_hbase_rows(scan_table_as_dict("global_attack_patterns"))

        return jsonify({
            "ip_stats": global_ip,
            "protocol_stats": global_protocol,
            "attack_patterns": global_patterns
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)