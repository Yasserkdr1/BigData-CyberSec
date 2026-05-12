from flask import Flask, jsonify, render_template, request
from cassandra.cluster import Cluster
from datetime import datetime
import happybase
import traceback

app = Flask(__name__)

# ============================================================
# CONFIGURATION
# ============================================================

# Speed Layer : Cassandra
CASSANDRA_HOST = "127.0.0.1"
CASSANDRA_PORT = 9042
CASSANDRA_KEYSPACE = "cybersec"

# Batch Layer : HBase via Thrift
HBASE_HOST = "127.0.0.1"
HBASE_PORT = 9090

# Une seule couche batch globale : plus de tables recent_*
TABLES = {
    "global_ip": "global_ip_stats",
    "global_protocol": "global_protocol_stats",
    "global_patterns": "global_attack_patterns",
    "ip_reputation": "ip_reputation",
    "target_ip_stats": "target_ip_stats",
    "threat_timeline": "threat_timeline",
    "attacker_victim_stats": "attacker_victim_stats",
    "high_risk_ips": "high_risk_ips",
    "ip_attack_types": "ip_attack_types",
    "ip_historical_alerts": "ip_historical_alerts",
}

cluster = Cluster([CASSANDRA_HOST], port=CASSANDRA_PORT)
session = cluster.connect(CASSANDRA_KEYSPACE)

# ============================================================
# HELPERS
# ============================================================

def safe_int(value, default=0):
    try:
        if value is None or value == "-" or value == "":
            return default
        return int(float(value))
    except Exception:
        return default


def safe_float(value, default=0.0):
    try:
        if value is None or value == "-" or value == "":
            return default
        return float(value)
    except Exception:
        return default


def hbase_connection():
    conn = happybase.Connection(HBASE_HOST, port=HBASE_PORT)
    conn.open()
    return conn


def decode_hbase_row(key, data):
    row_key = key.decode("utf-8") if isinstance(key, bytes) else str(key)
    row = {"key": row_key}

    for k, v in data.items():
        col = k.decode("utf-8") if isinstance(k, bytes) else str(k)
        val = v.decode("utf-8") if isinstance(v, bytes) else str(v)

        if col.startswith("cf:"):
            col = col[3:]

        row[col] = val

    return row


def scan_hbase_table(table_name, limit=None):
    conn = None
    try:
        conn = hbase_connection()
        table = conn.table(table_name)

        rows = []
        for idx, (key, data) in enumerate(table.scan()):
            if limit is not None and idx >= limit:
                break
            rows.append(decode_hbase_row(key, data))

        return rows

    except Exception as e:
        print(f"[HBase] Erreur scan table {table_name}: {e}")
        return []

    finally:
        if conn:
            conn.close()


def get_hbase_row(table_name, row_key):
    conn = None
    try:
        conn = hbase_connection()
        table = conn.table(table_name)
        data = table.row(str(row_key).encode("utf-8"))

        if not data:
            return None

        return decode_hbase_row(str(row_key).encode("utf-8"), data)

    except Exception as e:
        print(f"[HBase] Erreur get row {table_name}/{row_key}: {e}")
        return None

    finally:
        if conn:
            conn.close()


def sort_rows(rows, field="alert_count", reverse=True):
    return sorted(rows, key=lambda r: safe_float(r.get(field, 0)), reverse=reverse)


def scan_ip_historical_alerts(ip, limit=200):
    """
    Lit les alertes historiques détaillées d'une IP depuis HBase.
    Table attendue : ip_historical_alerts
    Rowkey attendu : source_ip|event_time|row_id
    """
    conn = None
    try:
        conn = hbase_connection()
        table = conn.table(TABLES["ip_historical_alerts"])
        rows = []

        prefix = (str(ip) + "|").encode("utf-8")

        for idx, (key, data) in enumerate(table.scan(row_prefix=prefix)):
            if idx >= limit:
                break
            rows.append(decode_hbase_row(key, data))

        rows.sort(
            key=lambda r: str(r.get("archived_at", r.get("event_time", ""))),
            reverse=True
        )

        return rows

    except Exception as e:
        print(f"[HBase] Erreur scan ip_historical_alerts pour {ip}: {e}")
        return []

    finally:
        if conn:
            conn.close()


def risk_distribution(ip_rows):
    dist = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for r in ip_rows:
        level = str(r.get("risk_level", "LOW")).upper()

        if level not in dist:
            score = safe_int(r.get("risk_score", 0))

            if score >= 80:
                level = "CRITICAL"
            elif score >= 60:
                level = "HIGH"
            elif score >= 30:
                level = "MEDIUM"
            else:
                level = "LOW"

        dist[level] += 1

    return [{"name": k, "value": v} for k, v in dist.items()]


def build_alerts_query(limit_value):
    return f"""
        SELECT alert_date, inserted_at, event_time, alert_type, source_ip, request_path,
               count_value, protocol, user_agent, dest_ip
        FROM realtime_alerts_live
        WHERE alert_date = ?
        LIMIT {limit_value}
    """


def fetch_today_alerts(limit_value=300):
    """
    Lit les alertes live du jour depuis Cassandra.
    Important :
    - inserted_at = heure réelle d'insertion / détection live
    - event_time = timestamp original du dataset
    Pour le dashboard temps réel, on privilégie inserted_at.
    """
    today = datetime.utcnow().date()
    prepared = session.prepare(build_alerts_query(limit_value))
    rows = session.execute(prepared, [today])

    alerts = []

    for r in rows:
        raw_time = r.inserted_at if r.inserted_at else r.event_time

        alerts.append({
            "display_time": raw_time.strftime("%H:%M:%S") if raw_time else "N/A",
            "raw_time": raw_time.isoformat() if raw_time else None,
            "alert_type": r.alert_type,
            "src_ip": r.source_ip,
            "dest_ip": r.dest_ip,
            "protocol": r.protocol,
            "path": r.request_path,
            "count_value": r.count_value,
            "user_agent": r.user_agent,
        })

    alerts.sort(key=lambda x: x["raw_time"] or "", reverse=True)
    return alerts


def count_today_alerts():
    today = datetime.utcnow().date()

    prepared = session.prepare("""
        SELECT COUNT(*)
        FROM realtime_alerts_live
        WHERE alert_date = ?
    """)

    row = session.execute(prepared, [today]).one()

    return int(row[0]) if row else 0


def fetch_live_alerts_by_ip(ip, limit_value=200):
    """
    Lit directement les alertes live d'une IP depuis Cassandra.
    Cette fonction évite de charger un lot global puis de filtrer côté Python.

    ALLOW FILTERING est acceptable pour une démonstration / petit volume.
    Pour une version production, créer une table Cassandra dédiée par source_ip.
    """
    query = f"""
        SELECT alert_date, inserted_at, event_time, alert_type, source_ip, request_path,
               count_value, protocol, user_agent, dest_ip
        FROM realtime_alerts_live
        WHERE alert_date = ?
        AND source_ip = ?
        LIMIT {limit_value}
        ALLOW FILTERING
    """

    today = datetime.utcnow().date()
    prepared = session.prepare(query)
    rows = session.execute(prepared, [today, ip])

    alerts = []

    for r in rows:
        raw_time = r.inserted_at if r.inserted_at else r.event_time

        alerts.append({
            "display_time": raw_time.strftime("%H:%M:%S") if raw_time else "N/A",
            "raw_time": raw_time.isoformat() if raw_time else None,
            "alert_type": r.alert_type,
            "src_ip": r.source_ip,
            "dest_ip": r.dest_ip,
            "protocol": r.protocol,
            "path": r.request_path,
            "count_value": r.count_value,
            "user_agent": r.user_agent,
        })

    alerts.sort(key=lambda x: x["raw_time"] or "", reverse=True)
    return alerts


def attach_live_last_seen_to_ips(ip_rows):
    """
    Ajoute à chaque IP batch un champ last_live.

    Objectif :
    - garder les statistiques historiques depuis HBase ;
    - remplacer l'affichage "Dernière activité" du dataset par l'heure réelle live ;
    - utiliser inserted_at venant de Cassandra, déjà exposé dans raw_time.

    Résultat ajouté dans chaque ligne :
    - last_live : date ISO de la dernière détection live de cette IP
    """
    try:
        live_alerts = fetch_today_alerts(1000)

        last_seen_by_ip = {}

        for alert in live_alerts:
            ip = alert.get("src_ip")
            raw_time = alert.get("raw_time")

            if not ip or not raw_time:
                continue

            if ip not in last_seen_by_ip or raw_time > last_seen_by_ip[ip]:
                last_seen_by_ip[ip] = raw_time

        for row in ip_rows:
            ip = row.get("key") or row.get("source_ip") or row.get("src_ip")
            row["last_live"] = last_seen_by_ip.get(ip)

        return ip_rows

    except Exception as e:
        print(f"[Live] Impossible d'attacher last_live aux IP batch: {e}")

        for row in ip_rows:
            row["last_live"] = None

        return ip_rows


def is_scan_alert(alert_type):
    t = str(alert_type or "").upper()
    return any(x in t for x in [
        "NMAP",
        "MASSCAN",
        "NIKTO",
        "NESSUS",
        "WPSCAN",
        "ACUNETIX",
        "SCAN"
    ])


def is_sqli_alert(alert_type):
    t = str(alert_type or "").upper()
    return "SQL" in t or "SQLMAP" in t


def is_xss_alert(alert_type):
    return "XSS" in str(alert_type or "").upper()


def is_bruteforce_alert(alert_type):
    t = str(alert_type or "").upper()
    return "BRUTE" in t or "BLOCKED" in t or "LOGIN" in t


def is_exfil_alert(alert_type):
    return "EXFIL" in str(alert_type or "").upper()


def live_summary(alerts):
    dests = set(
        a.get("dest_ip")
        for a in alerts
        if a.get("dest_ip") and a.get("dest_ip") != "-"
    )

    protocols = set(
        a.get("protocol")
        for a in alerts
        if a.get("protocol") and a.get("protocol") != "-"
    )

    attack_types = {}
    protocol_counts = {}
    dest_counts = {}

    for a in alerts:
        at = a.get("alert_type") or "-"
        pr = a.get("protocol") or "-"
        de = a.get("dest_ip") or "-"

        attack_types[at] = attack_types.get(at, 0) + 1
        protocol_counts[pr] = protocol_counts.get(pr, 0) + 1
        dest_counts[de] = dest_counts.get(de, 0) + 1

    return {
        "active_alerts": len(alerts),
        "last_seen": alerts[0]["raw_time"] if alerts else None,
        "unique_targets_live": len(dests),
        "unique_protocols_live": len(protocols),
        "scan_live": sum(1 for a in alerts if is_scan_alert(a.get("alert_type"))),
        "sqli_live": sum(1 for a in alerts if is_sqli_alert(a.get("alert_type"))),
        "xss_live": sum(1 for a in alerts if is_xss_alert(a.get("alert_type"))),
        "bruteforce_live": sum(1 for a in alerts if is_bruteforce_alert(a.get("alert_type"))),
        "exfiltration_live": sum(1 for a in alerts if is_exfil_alert(a.get("alert_type"))),
        "recent_attack_types": attack_types,
        "protocol_counts": protocol_counts,
        "destination_counts": dest_counts,
        "alerts": alerts[:100],
    }


def build_recommendation(historical, live):
    score = safe_int((historical or {}).get("risk_score", 0))
    recent_count = safe_int(live.get("active_alerts", 0))
    scan_live = safe_int(live.get("scan_live", 0))
    sqli_live = safe_int(live.get("sqli_live", 0))

    if score >= 80 or recent_count >= 10 or sqli_live >= 5:
        return {
            "level": "CRITICAL",
            "action": "BLOCK_IP",
            "reason": "Score historique critique ou forte activité live détectée."
        }

    if score >= 60 or recent_count >= 5 or scan_live >= 4:
        return {
            "level": "HIGH",
            "action": "MONITOR_AND_RATE_LIMIT",
            "reason": "Risque élevé : surveiller activement et limiter le trafic."
        }

    if score >= 30 or recent_count > 0:
        return {
            "level": "MEDIUM",
            "action": "MONITOR",
            "reason": "Score modéré ou activité live récente : garder sous surveillance."
        }

    return {
        "level": "LOW",
        "action": "NO_ACTION",
        "reason": "Aucun signal critique dans les vues actuelles."
    }


# ============================================================
# ROUTES UI
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


# ============================================================
# API SPEED LAYER
# ============================================================

@app.route("/api/alerts")
def api_alerts():
    try:
        allowed_limits = {20, 50, 100, 200, 300, 500, 1000}

        try:
            limit_value = int(request.args.get("limit", 100))
        except ValueError:
            limit_value = 100

        if limit_value not in allowed_limits:
            limit_value = 100

        alerts = fetch_today_alerts(limit_value)
        total_count = count_today_alerts()

        return jsonify({
            "limit": limit_value,
            "count": len(alerts),
            "total_count": total_count,
            "alerts": alerts
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ============================================================
# API BATCH LAYER
# ============================================================

@app.route("/api/batch/analytics")
def api_batch_analytics():
    try:
        # ============================================================
        # IMPORTANT
        # ============================================================
        # Les listes *_all contiennent TOUTES les lignes HBase.
        # Elles servent aux KPI du dashboard : vrais compteurs HBase.
        #
        # Les listes sans suffixe sont limitées pour l'affichage :
        # - Top IPs dangereuses : Top 100
        # - Machines ciblées : Top 100
        # - Relations source -> destination : Top 100
        # - Protocoles : Top 50
        # - Patterns : Top 80
        # ============================================================

        ip_reputation_all = sort_rows(
            scan_hbase_table(TABLES["ip_reputation"]),
            "risk_score"
        )

        # Affichage tableau : Top 100 seulement.
        ip_reputation = ip_reputation_all[:100]

        # On garde les stats batch HBase, puis on ajoute last_live depuis Cassandra.
        ip_reputation = attach_live_last_seen_to_ips(ip_reputation)

        high_risk_ips_all = sort_rows(
            scan_hbase_table(TABLES["high_risk_ips"]),
            "risk_score"
        )

        # Si la table high_risk_ips n'est pas remplie, fallback depuis toutes les IP.
        if not high_risk_ips_all:
            high_risk_ips_all = [
                r for r in ip_reputation_all
                if safe_int(r.get("risk_score", 0)) >= 60
            ]

        # Affichage graphe/table : Top 100 seulement.
        high_risk_ips = high_risk_ips_all[:100]
        high_risk_ips = attach_live_last_seen_to_ips(high_risk_ips)

        target_ip_stats_raw = scan_hbase_table(TABLES["target_ip_stats"])

        # Ligne spéciale écrite par le batch : vrai total des IP destinations distinctes.
        # Elle n'est pas affichée dans les tableaux ni les graphes.
        target_kpi_row = next(
            (r for r in target_ip_stats_raw if r.get("key") == "__KPI_TOTAL__" or r.get("row_type") == "kpi"),
            None
        )

        target_ip_stats_all = sort_rows(
            [
                r for r in target_ip_stats_raw
                if r.get("key") != "__KPI_TOTAL__" and r.get("row_type") != "kpi"
            ],
            "target_risk_score"
        )

        # Affichage machines ciblées : le batch stocke déjà le Top 50.
        target_ip_stats = target_ip_stats_all[:100]

        target_ip_stats_total = safe_int(
            target_kpi_row.get("total_unique_targets") if target_kpi_row else None,
            len(target_ip_stats_all)
        )

        threat_timeline_all = sort_rows(
            scan_hbase_table(TABLES["threat_timeline"]),
            "key",
            reverse=False
        )

        # Timeline : on renvoie tout, car le graphe JS limite déjà avec slice(-24).
        threat_timeline = threat_timeline_all

        attacker_victim_stats_all = sort_rows(
            scan_hbase_table(TABLES["attacker_victim_stats"]),
            "relation_risk_score"
        )

        # Affichage relations : Top 100 seulement.
        attacker_victim_stats = attacker_victim_stats_all[:100]

        global_protocol_stats_all = sort_rows(
            scan_hbase_table(TABLES["global_protocol"]),
            "alert_count"
        )

        # Affichage protocoles : Top 50 seulement.
        global_protocol_stats = global_protocol_stats_all[:50]

        global_attack_patterns_all = sort_rows(
            scan_hbase_table(TABLES["global_patterns"]),
            "alert_count"
        )

        # Affichage patterns : Top 80 seulement.
        global_attack_patterns = global_attack_patterns_all[:80]

        return jsonify({
            # Données limitées pour tableaux et graphiques
            "ip_reputation": ip_reputation,
            "high_risk_ips": high_risk_ips,
            "target_ip_stats": target_ip_stats,
            "threat_timeline": threat_timeline,
            "attacker_victim_stats": attacker_victim_stats,
            "global_protocol_stats": global_protocol_stats,
            "global_attack_patterns": global_attack_patterns,

            # Vrais compteurs HBase pour les KPI
            "ip_reputation_total": len(ip_reputation_all),
            "high_risk_ips_total": len(high_risk_ips_all),
            "target_ip_stats_total": target_ip_stats_total,
            "threat_timeline_total": len(threat_timeline_all),
            "attacker_victim_stats_total": len(attacker_victim_stats_all),
            "global_protocol_stats_total": len(global_protocol_stats_all),
            "global_attack_patterns_total": len(global_attack_patterns_all),

            # Distribution calculée sur toutes les IP, pas seulement le Top 100
            "risk_distribution": risk_distribution(ip_reputation_all),
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# Compatibilité éventuelle avec anciens appels, mais le dashboard ne l'utilise plus.
@app.route("/api/batch/global")
def api_batch_global():
    try:
        return jsonify({
            "ip_stats": sort_rows(
                scan_hbase_table(TABLES["global_ip"]),
                "alert_count"
            )[:100],
            "protocol_stats": sort_rows(
                scan_hbase_table(TABLES["global_protocol"]),
                "alert_count"
            )[:100],
            "attack_patterns": sort_rows(
                scan_hbase_table(TABLES["global_patterns"]),
                "alert_count"
            )[:100],
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# ============================================================
# API IP INVESTIGATION : BATCH + SPEED, SANS MELANGE
# ============================================================

@app.route("/api/threat/ip/<ip>")
def api_threat_ip(ip):
    try:
        historical = get_hbase_row(TABLES["ip_reputation"], ip)

        if historical is None:
            fallback = get_hbase_row(TABLES["global_ip"], ip)
            historical = fallback or {"key": ip}

        ip_live_alerts = fetch_live_alerts_by_ip(ip, 200)
        live = live_summary(ip_live_alerts)

        relations = []

        for r in scan_hbase_table(TABLES["attacker_victim_stats"]):
            if r.get("src_ip") == ip or str(r.get("key", "")).startswith(ip + "|"):
                relations.append(r)

        relations = sort_rows(relations, "relation_risk_score")[:30]

        historical_attack_types = []

        for r in scan_hbase_table(TABLES["ip_attack_types"]):
            if r.get("src_ip") == ip or str(r.get("key", "")).startswith(ip + "|"):
                historical_attack_types.append(r)

        historical_attack_types = sort_rows(
            historical_attack_types,
            "alert_count"
        )[:50]

        historical_alerts = scan_ip_historical_alerts(ip, limit=200)

        recommendation = build_recommendation(historical, live)

        combined = {
            "total_alerts_visible": safe_int(
                historical.get("total_alerts", historical.get("alert_count", 0))
            ) + live["active_alerts"],

            "scan_total_visible": safe_int(
                historical.get("scan_count", 0)
            ) + live["scan_live"],

            "sqli_total_visible": safe_int(
                historical.get("sqli_count", 0)
            ) + live["sqli_live"],

            "xss_total_visible": safe_int(
                historical.get("xss_count", 0)
            ) + live["xss_live"],

            "note": (
                "Les totaux combinés additionnent les compteurs historiques HBase "
                "et les alertes live affichées. Les cibles/protocoles restent séparés "
                "pour éviter les doublons invisibles."
            )
        }

        return jsonify({
            "ip": ip,
            "historical": historical,
            "live": live,
            "combined": combined,
            "relations": relations,
            "historical_attack_types": historical_attack_types,
            "historical_alerts": historical_alerts,
            "recommendation": recommendation,
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)