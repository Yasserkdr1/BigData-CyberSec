from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, lower, when, count, lit, sum as spark_sum,
    countDistinct, min as spark_min, max as spark_max,
    to_timestamp, date_format, round as spark_round,
    current_timestamp, coalesce, sha2, concat_ws,window
)
import happybase


HDFS_PATH = "hdfs://hadoop-master:9000/data/cybersecurity/logs"

HBASE_HOST = "hadoop-master"
HBASE_PORT = 9090

TOP_N = 50
HISTORICAL_ALERT_LIMIT = 20000


# =========================
# Spark session
# =========================

spark = SparkSession.builder \
    .appName("GlobalThreatAnalyticsEnrichedToHBase") \
    .master("local[*]") \
    .config("spark.sql.shuffle.partitions", "8") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")


# =========================
# Lecture HDFS
# =========================
# recursiveFileLookup permet de lire les fichiers Parquet même si HDFS est partitionné
# par year/month/day/hour.

df = spark.read.option("recursiveFileLookup", "true").parquet(HDFS_PATH)

# event_time = heure originale du log dans le dataset.
# archived_at = heure réelle où le log a été archivé dans HDFS par KafkaToHDFSArchive.
# Si archived_at n'existe pas dans d'anciens fichiers, on met current_timestamp() comme fallback.

if "event_time" in df.columns:
    df = df.withColumn("event_time", coalesce(to_timestamp(col("event_time")), to_timestamp(col("timestamp"))))
else:
    df = df.withColumn("event_time", to_timestamp(col("timestamp")))

if "archived_at" in df.columns:
    df = df.withColumn("archived_at", to_timestamp(col("archived_at")))
else:
    df = df.withColumn("archived_at", current_timestamp())

# Normalisation des colonnes

df = df.withColumn("source_ip", col("source_ip").cast("string")) \
       .withColumn("dest_ip", col("dest_ip").cast("string")) \
       .withColumn("protocol", col("protocol").cast("string")) \
       .withColumn("action", lower(col("action"))) \
       .withColumn("threat_label", lower(col("threat_label"))) \
       .withColumn("user_agent", col("user_agent").cast("string")) \
       .withColumn("request_path", col("request_path").cast("string")) \
       .withColumn("bytes_transferred", col("bytes_transferred").cast("long"))

ua = lower(col("user_agent"))
path = lower(col("request_path"))
action_col = lower(col("action"))

print("=== TOTAL LOGS GLOBAL ===")
print(df.count())


# =========================
# 1. Détection par signatures
# =========================

instant_alerts = df.withColumn(
    "alert_type",
    when(ua.contains("sqlmap"), "SQLMAP")
    .when(ua.contains("nikto"), "NIKTO")
    .when(ua.contains("nmap"), "NMAP")
    .when(ua.contains("masscan"), "MASSCAN")
    .when(ua.contains("nessus"), "NESSUS")
    .when(ua.contains("wpscan"), "WPSCAN")
    .when(ua.contains("acunetix"), "ACUNETIX")
    .when(ua.contains("metasploit"), "METASPLOIT")

    .when(path.rlike(r"(?i)\bor\b\s+1=1"), "SQLI_TAUTOLOGY")
    .when(path.rlike(r"(?i)union\s+select"), "SQLI_UNION")
    .when(path.rlike(r"(?i)information_schema"), "SQLI_INFO_SCHEMA")
    .when(path.rlike(r"(?i)sleep\s*\("), "SQLI_TIME_BASED")
    .when(path.rlike(r"(?i)benchmark\s*\("), "SQLI_BENCHMARK")
    .when(path.rlike(r"(?i)xp_cmdshell"), "SQLI_XP_CMDSHELL")

    .when(path.rlike(r"(?i)<script"), "XSS_SCRIPT")
    .when(path.rlike(r"(?i)javascript:"), "XSS_JS_URI")
    .when(path.rlike(r"(?i)onerror\s*="), "XSS_ONERROR")
    .when(path.rlike(r"(?i)onload\s*="), "XSS_ONLOAD")
    .when(path.rlike(r"(?i)alert\s*\("), "XSS_ALERT")

    .when(path.rlike(r"\.\./"), "PATH_TRAVERSAL")
    .when(path.rlike(r"(?i)\.\.%2f"), "PATH_TRAVERSAL_ENCODED")
    .when(path.rlike(r"(?i)/etc/passwd"), "ETC_PASSWD_ACCESS")
    .when(path.rlike(r"(?i)win\.ini"), "WIN_INI_ACCESS")
    .when(path.rlike(r"(?i)/proc/self/environ"), "PROC_ENVIRON_ACCESS")

    .when(path.rlike(r"(?i)phpmyadmin"), "PHPMYADMIN")
    .when(path.rlike(r"(?i)wp-login\.php"), "WP_LOGIN")
    .when(path.rlike(r"(?i)xmlrpc\.php"), "XMLRPC_PROBE")
    .when(path.rlike(r"(?i)backup\.sql"), "BACKUP_FILE")
    .when(path.rlike(r"(?i)\.env"), "ENV_FILE_ACCESS")
    .when(path.rlike(r"(?i)\.git"), "GIT_DISCLOSURE")
    .when(path.rlike(r"(?i)/admin"), "ADMIN_ACCESS")

    .when(path.rlike(r"(?i)(cmd|exec|command)\s*="), "CMD_INJECTION")
    .when(path.rlike(r"(?i)powershell"), "POWERSHELL_PAYLOAD")
    .when(path.rlike(r"(?i)wget\s+http"), "WGET_PAYLOAD")
    .when(path.rlike(r"(?i)curl\s+http"), "CURL_PAYLOAD")
    .when(path.rlike(r"(?i)certutil"), "CERTUTIL_PAYLOAD")
).filter(col("alert_type").isNotNull()) \
 .select(
    col("source_ip").alias("src_ip"),
    col("dest_ip"),
    col("protocol"),
    col("request_path").alias("path"),
    col("alert_type"),
    col("event_time"),
    col("archived_at"),
    col("bytes_transferred"),
    col("threat_label"),
    col("action")
)


# =========================
# 2. Activité bloquée répétée globale
# =========================

bruteforce_alerts = df.filter(action_col == "blocked") \
    .groupBy(
        window(col("archived_at"), "1 minute", "10 seconds"),
        col("source_ip"),
        col("protocol")
    ) \
    .agg(
        count("*").alias("failed_attempts"),
        spark_sum("bytes_transferred").alias("bytes_transferred"),
        spark_max("event_time").alias("event_time"),
        spark_max("archived_at").alias("archived_at")
    ) \
    .filter(col("failed_attempts") >= 5) \
    .select(
        col("source_ip").alias("src_ip"),
        lit("-").alias("dest_ip"),
        col("protocol"),
        lit("authentication-target").alias("path"),
        lit("REPEATED_BLOCKED_ACTIVITY").alias("alert_type"),
        col("event_time"),
        col("archived_at"),
        col("bytes_transferred"),
        lit("suspicious").alias("threat_label"),
        lit("blocked").alias("action")
    )


# =========================
# 3. Volume anormal global
# =========================

volume_alerts = df.groupBy(
        col("source_ip"),
        col("protocol")
    ) \
    .agg(
        spark_sum("bytes_transferred").alias("total_bytes"),
        spark_max("event_time").alias("event_time"),
        spark_max("archived_at").alias("archived_at")
    ) \
    .filter(col("total_bytes") > 10 * 1024 * 1024) \
    .select(
        col("source_ip").alias("src_ip"),
        lit("-").alias("dest_ip"),
        col("protocol"),
        lit("high-volume-transfer").alias("path"),
        lit("DATA_EXFILTRATION").alias("alert_type"),
        col("event_time"),
        col("archived_at"),
        col("total_bytes").alias("bytes_transferred"),
        lit("malicious").alias("threat_label"),
        lit("allowed").alias("action")
    )


# =========================
# Toutes les alertes batch
# =========================

all_alerts = instant_alerts.unionByName(bruteforce_alerts).unionByName(volume_alerts)
all_alerts = all_alerts.cache()

print("=== TOTAL ALERTS BATCH ===")
print(all_alerts.count())


# =========================
# Catégories d'attaque
# =========================

categorized_alerts = all_alerts.withColumn(
    "attack_category",
    when(col("alert_type").startswith("SQLI") | (col("alert_type") == "SQLMAP"), "SQLI")
    .when(col("alert_type").startswith("XSS"), "XSS")
    .when(col("alert_type").isin("NMAP", "MASSCAN", "NIKTO", "NESSUS", "WPSCAN", "ACUNETIX"), "SCAN")
    .when(col("alert_type") == "REPEATED_BLOCKED_ACTIVITY", "BRUTE_FORCE")
    .when(col("alert_type") == "DATA_EXFILTRATION", "EXFILTRATION")
    .when(col("alert_type").isin("PATH_TRAVERSAL", "PATH_TRAVERSAL_ENCODED", "ETC_PASSWD_ACCESS", "WIN_INI_ACCESS", "PROC_ENVIRON_ACCESS"), "FILE_ACCESS_ATTACK")
    .when(col("alert_type").isin("ADMIN_ACCESS", "WP_LOGIN", "PHPMYADMIN", "XMLRPC_PROBE"), "ADMIN_PROBING")
    .when(col("alert_type").isin("GIT_DISCLOSURE", "ENV_FILE_ACCESS", "BACKUP_FILE"), "SENSITIVE_FILE_DISCLOSURE")
    .when(col("alert_type").isin("CMD_INJECTION", "POWERSHELL_PAYLOAD", "WGET_PAYLOAD", "CURL_PAYLOAD", "CERTUTIL_PAYLOAD"), "COMMAND_INJECTION")
    .otherwise("OTHER")
).withColumn("is_sqli", when(col("attack_category") == "SQLI", 1).otherwise(0)) \
 .withColumn("is_xss", when(col("attack_category") == "XSS", 1).otherwise(0)) \
 .withColumn("is_scan", when(col("attack_category") == "SCAN", 1).otherwise(0)) \
 .withColumn("is_bruteforce", when(col("attack_category") == "BRUTE_FORCE", 1).otherwise(0)) \
 .withColumn("is_exfiltration", when(col("attack_category") == "EXFILTRATION", 1).otherwise(0)) \
 .withColumn("is_file_attack", when(col("attack_category") == "FILE_ACCESS_ATTACK", 1).otherwise(0)) \
 .withColumn("is_admin_probe", when(col("attack_category") == "ADMIN_PROBING", 1).otherwise(0)) \
 .withColumn("is_sensitive_file", when(col("attack_category") == "SENSITIVE_FILE_DISCLOSURE", 1).otherwise(0)) \
 .withColumn("is_command_injection", when(col("attack_category") == "COMMAND_INJECTION", 1).otherwise(0)) \
 .withColumn("is_malicious", when(col("threat_label") == "malicious", 1).otherwise(0)) \
 .withColumn("is_suspicious", when(col("threat_label") == "suspicious", 1).otherwise(0)) \
 .withColumn("is_blocked", when(col("action") == "blocked", 1).otherwise(0))


# =========================
# A. IP reputation
# =========================

ip_reputation = categorized_alerts.groupBy("src_ip") \
    .agg(
        count("*").alias("total_alerts"),
        spark_sum("is_malicious").alias("malicious_count"),
        spark_sum("is_suspicious").alias("suspicious_count"),
        spark_sum("is_blocked").alias("blocked_count"),
        spark_sum("is_sqli").alias("sqli_count"),
        spark_sum("is_xss").alias("xss_count"),
        spark_sum("is_scan").alias("scan_count"),
        spark_sum("is_bruteforce").alias("bruteforce_count"),
        spark_sum("is_exfiltration").alias("exfiltration_count"),
        spark_sum("is_file_attack").alias("file_attack_count"),
        spark_sum("is_admin_probe").alias("admin_probe_count"),
        spark_sum("is_sensitive_file").alias("sensitive_file_count"),
        spark_sum("is_command_injection").alias("command_injection_count"),
        spark_sum("bytes_transferred").alias("total_bytes"),
        countDistinct("dest_ip").alias("unique_targets"),
        countDistinct("protocol").alias("unique_protocols"),
        spark_min("event_time").alias("first_seen"),
        spark_max("event_time").alias("last_seen"),
        spark_min("archived_at").alias("first_archived_at"),
        spark_max("archived_at").alias("last_archived_at")
    ) \
    .withColumn(
        "risk_score_raw",
        col("malicious_count") * 5 +
        col("suspicious_count") * 2 +
        col("blocked_count") * 1 +
        col("sqli_count") * 4 +
        col("xss_count") * 3 +
        col("scan_count") * 3 +
        col("bruteforce_count") * 4 +
        col("exfiltration_count") * 6 +
        col("file_attack_count") * 4 +
        col("admin_probe_count") * 2 +
        col("sensitive_file_count") * 4 +
        col("command_injection_count") * 5 +
        col("unique_targets") * 2
    ) \
    .withColumn("risk_score", when(col("risk_score_raw") > 100, 100).otherwise(col("risk_score_raw"))) \
    .withColumn(
        "risk_level",
        when(col("risk_score") >= 80, "CRITICAL")
        .when(col("risk_score") >= 60, "HIGH")
        .when(col("risk_score") >= 30, "MEDIUM")
        .otherwise("LOW")
    ) \
    .orderBy(col("risk_score").desc(), col("total_alerts").desc())


# =========================
# B. Global IP stats
# =========================

global_ip_stats = categorized_alerts.groupBy("src_ip") \
    .agg(
        count("*").alias("alert_count"),
        spark_sum("is_malicious").alias("malicious_count"),
        spark_sum("is_suspicious").alias("suspicious_count"),
        spark_sum("is_sqli").alias("sqli_count"),
        spark_sum("is_xss").alias("xss_count"),
        spark_sum("is_scan").alias("scan_count"),
        spark_sum("is_bruteforce").alias("bruteforce_count"),
        spark_sum("is_exfiltration").alias("exfiltration_count"),
        spark_sum("is_file_attack").alias("file_attack_count"),
        spark_sum("is_admin_probe").alias("admin_probe_count"),
        spark_sum("is_sensitive_file").alias("sensitive_file_count"),
        spark_sum("is_command_injection").alias("command_injection_count")
    ) \
    .orderBy(col("alert_count").desc()) \
    .limit(TOP_N)


# =========================
# C. Protocol stats
# =========================

global_protocol_stats = categorized_alerts.groupBy("protocol") \
    .agg(
        count("*").alias("alert_count"),
        spark_sum("is_malicious").alias("malicious_count"),
        spark_sum("is_suspicious").alias("suspicious_count"),
        spark_sum("is_blocked").alias("blocked_count"),
        spark_sum("is_sqli").alias("sqli_count"),
        spark_sum("is_xss").alias("xss_count"),
        spark_sum("is_scan").alias("scan_count"),
        spark_sum("is_bruteforce").alias("bruteforce_count"),
        spark_sum("is_exfiltration").alias("exfiltration_count"),
        spark_sum("is_file_attack").alias("file_attack_count"),
        spark_sum("is_admin_probe").alias("admin_probe_count"),
        spark_sum("is_sensitive_file").alias("sensitive_file_count"),
        spark_sum("is_command_injection").alias("command_injection_count"),
        spark_sum("bytes_transferred").alias("total_bytes"),
        spark_round(spark_sum("bytes_transferred") / count("*"), 2).alias("avg_bytes_per_alert")
    ) \
    .orderBy(col("alert_count").desc())


# =========================
# D. Attack patterns
# =========================

global_attack_patterns = categorized_alerts.groupBy("alert_type", "attack_category") \
    .agg(
        count("*").alias("alert_count"),
        countDistinct("src_ip").alias("unique_attackers"),
        countDistinct("dest_ip").alias("unique_targets"),
        spark_sum("bytes_transferred").alias("total_bytes"),
        spark_max("event_time").alias("last_seen"),
        spark_max("archived_at").alias("last_archived_at")
    ) \
    .orderBy(col("alert_count").desc())


# =========================
# E. Types de menaces par IP source
# =========================

ip_attack_types = categorized_alerts.groupBy("src_ip", "alert_type", "attack_category") \
    .agg(
        count("*").alias("alert_count"),
        countDistinct("dest_ip").alias("unique_targets"),
        countDistinct("protocol").alias("unique_protocols"),
        spark_sum("bytes_transferred").alias("total_bytes"),
        spark_max("event_time").alias("last_seen"),
        spark_max("archived_at").alias("last_archived_at")
    ) \
    .orderBy(col("alert_count").desc())


# =========================
# E2. Alertes historiques détaillées par IP
# =========================
# Cette table garde les deux dates :
# - archived_at : date réelle d'archivage dans HDFS
# - event_time  : date originale du log dans le dataset

ip_historical_alerts = categorized_alerts.withColumn(
    "row_hash",
    sha2(concat_ws("|",
        col("src_ip"), col("dest_ip"), col("protocol"), col("path"),
        col("alert_type"), col("event_time").cast("string"), col("archived_at").cast("string")
    ), 256)
).select(
    "row_hash",
    "src_ip",
    "dest_ip",
    "protocol",
    "path",
    "alert_type",
    "attack_category",
    "event_time",
    "archived_at",
    "bytes_transferred"
).orderBy(col("archived_at").desc(), col("event_time").desc()).limit(HISTORICAL_ALERT_LIMIT)


# =========================
# KPI global : nombre réel d'IP destinations distinctes
# =========================
# La table target_ip_stats reste limitée au Top 50 pour l'affichage.
# Cette valeur est stockée dans une ligne spéciale HBase pour alimenter le KPI du dashboard.

total_unique_targets = categorized_alerts.filter(
    (col("dest_ip").isNotNull()) & (col("dest_ip") != "-")
).select("dest_ip").distinct().count()


# =========================
# F. IP destinations les plus attaquées
# =========================

target_ip_stats = categorized_alerts.filter(col("dest_ip") != "-") \
    .groupBy("dest_ip") \
    .agg(
        count("*").alias("alert_count"),
        countDistinct("src_ip").alias("unique_attackers"),
        countDistinct("protocol").alias("unique_protocols"),
        spark_sum("is_malicious").alias("malicious_count"),
        spark_sum("is_suspicious").alias("suspicious_count"),
        spark_sum("is_sqli").alias("sqli_count"),
        spark_sum("is_xss").alias("xss_count"),
        spark_sum("is_scan").alias("scan_count"),
        spark_sum("is_exfiltration").alias("exfiltration_count"),
        spark_sum("is_file_attack").alias("file_attack_count"),
        spark_sum("is_admin_probe").alias("admin_probe_count"),
        spark_sum("is_sensitive_file").alias("sensitive_file_count"),
        spark_sum("is_command_injection").alias("command_injection_count"),
        spark_sum("bytes_transferred").alias("total_bytes"),
        spark_max("event_time").alias("last_seen"),
        spark_max("archived_at").alias("last_archived_at")
    ) \
    .withColumn(
        "target_risk_score_raw",
        col("alert_count") * 1 +
        col("unique_attackers") * 3 +
        col("malicious_count") * 5 +
        col("sqli_count") * 4 +
        col("xss_count") * 3 +
        col("scan_count") * 3 +
        col("exfiltration_count") * 6 +
        col("file_attack_count") * 4 +
        col("admin_probe_count") * 2 +
        col("sensitive_file_count") * 4 +
        col("command_injection_count") * 5
    ) \
    .withColumn("target_risk_score", when(col("target_risk_score_raw") > 100, 100).otherwise(col("target_risk_score_raw"))) \
    .orderBy(col("target_risk_score").desc(), col("alert_count").desc()) \
    .limit(TOP_N)


# =========================
# G. Timeline des menaces par minute
# =========================
# On garde event_time pour l'historique métier du dataset.
# Si tu veux une timeline de démonstration par minute d'archivage, remplace event_time par archived_at.

threat_timeline = categorized_alerts.withColumn(
        "time_bucket",
        date_format(col("archived_at"), "yyyy-MM-dd HH:mm:00")
    ) \
    .groupBy("time_bucket") \
    .agg(
        count("*").alias("total_alerts"),
        spark_sum("is_malicious").alias("malicious_count"),
        spark_sum("is_suspicious").alias("suspicious_count"),
        spark_sum("is_sqli").alias("sqli_count"),
        spark_sum("is_xss").alias("xss_count"),
        spark_sum("is_scan").alias("scan_count"),
        spark_sum("is_bruteforce").alias("bruteforce_count"),
        spark_sum("is_exfiltration").alias("exfiltration_count"),
        spark_sum("is_file_attack").alias("file_attack_count"),
        spark_sum("is_admin_probe").alias("admin_probe_count"),
        spark_sum("is_sensitive_file").alias("sensitive_file_count"),
        spark_sum("is_command_injection").alias("command_injection_count"),
        countDistinct("src_ip").alias("unique_attackers"),
        countDistinct("dest_ip").alias("unique_targets"),
        spark_min("event_time").alias("first_event_time"),
        spark_max("event_time").alias("last_event_time"),
        spark_min("archived_at").alias("first_archived_at"),
        spark_max("archived_at").alias("last_archived_at")
    ) \
    .orderBy("time_bucket")


# =========================
# H. Couples attaquant -> victime
# =========================

attacker_victim_stats = categorized_alerts.filter(col("dest_ip") != "-") \
    .groupBy("src_ip", "dest_ip") \
    .agg(
        count("*").alias("alert_count"),
        countDistinct("protocol").alias("unique_protocols"),
        spark_sum("is_malicious").alias("malicious_count"),
        spark_sum("is_suspicious").alias("suspicious_count"),
        spark_sum("is_sqli").alias("sqli_count"),
        spark_sum("is_xss").alias("xss_count"),
        spark_sum("is_scan").alias("scan_count"),
        spark_sum("is_exfiltration").alias("exfiltration_count"),
        spark_sum("is_file_attack").alias("file_attack_count"),
        spark_sum("is_admin_probe").alias("admin_probe_count"),
        spark_sum("is_sensitive_file").alias("sensitive_file_count"),
        spark_sum("is_command_injection").alias("command_injection_count"),
        spark_sum("bytes_transferred").alias("total_bytes"),
        spark_max("event_time").alias("last_seen"),
        spark_max("archived_at").alias("last_archived_at")
    ) \
    .withColumn(
        "relation_risk_score_raw",
        col("alert_count") * 1 +
        col("malicious_count") * 5 +
        col("sqli_count") * 4 +
        col("xss_count") * 3 +
        col("scan_count") * 3 +
        col("exfiltration_count") * 6 +
        col("file_attack_count") * 4 +
        col("admin_probe_count") * 2 +
        col("sensitive_file_count") * 4 +
        col("command_injection_count") * 5
    ) \
    .withColumn("relation_risk_score", when(col("relation_risk_score_raw") > 100, 100).otherwise(col("relation_risk_score_raw"))) \
    .orderBy(col("relation_risk_score").desc(), col("alert_count").desc()) \
    .limit(TOP_N)


# =========================
# I. High risk IPs
# =========================

high_risk_ips = ip_reputation.filter(col("risk_score") >= 60) \
    .orderBy(col("risk_score").desc()) \
    .limit(TOP_N)


# =========================
# Helpers HBase
# =========================

def clean_table(table):
    for key, _ in table.scan():
        table.delete(key)


def safe_value(value):
    if value is None:
        return "-"
    return str(value)


def put_rows(table, rows, rowkey_func, columns_func):
    batch = table.batch(batch_size=1000)
    counter = 0
    for row in rows:
        row_key = rowkey_func(row).encode()
        cols = columns_func(row)
        batch.put(row_key, {
            ("cf:" + k).encode(): safe_value(v).encode()
            for k, v in cols.items()
        })
        counter += 1
    batch.send()
    return counter


# =========================
# Connexion HBase
# =========================

connection = happybase.Connection(HBASE_HOST, port=HBASE_PORT)
connection.open()

tables = {
    "ip_reputation": connection.table("ip_reputation"),
    "global_ip_stats": connection.table("global_ip_stats"),
    "global_protocol_stats": connection.table("global_protocol_stats"),
    "global_attack_patterns": connection.table("global_attack_patterns"),
    "target_ip_stats": connection.table("target_ip_stats"),
    "threat_timeline": connection.table("threat_timeline"),
    "attacker_victim_stats": connection.table("attacker_victim_stats"),
    "high_risk_ips": connection.table("high_risk_ips"),
    "ip_attack_types": connection.table("ip_attack_types"),
    "ip_historical_alerts": connection.table("ip_historical_alerts")
}

print("Nettoyage des anciennes vues HBase...")
for table in tables.values():
    clean_table(table)


# =========================
# Écritures HBase
# =========================

print("Ecriture ip_reputation...")
put_rows(
    tables["ip_reputation"],
    ip_reputation.collect(),
    lambda r: r["src_ip"],
    lambda r: {
        "total_alerts": r["total_alerts"],
        "malicious_count": r["malicious_count"],
        "suspicious_count": r["suspicious_count"],
        "blocked_count": r["blocked_count"],
        "sqli_count": r["sqli_count"],
        "xss_count": r["xss_count"],
        "scan_count": r["scan_count"],
        "bruteforce_count": r["bruteforce_count"],
        "exfiltration_count": r["exfiltration_count"],
        "file_attack_count": r["file_attack_count"],
        "admin_probe_count": r["admin_probe_count"],
        "sensitive_file_count": r["sensitive_file_count"],
        "command_injection_count": r["command_injection_count"],
        "total_bytes": r["total_bytes"],
        "unique_targets": r["unique_targets"],
        "unique_protocols": r["unique_protocols"],
        "first_seen": r["first_seen"],
        "last_seen": r["last_seen"],
        "first_archived_at": r["first_archived_at"],
        "last_archived_at": r["last_archived_at"],
        "risk_score": r["risk_score"],
        "risk_level": r["risk_level"]
    }
)

print("Ecriture global_ip_stats...")
put_rows(
    tables["global_ip_stats"],
    global_ip_stats.collect(),
    lambda r: r["src_ip"],
    lambda r: {
        "alert_count": r["alert_count"],
        "malicious_count": r["malicious_count"],
        "suspicious_count": r["suspicious_count"],
        "sqli_count": r["sqli_count"],
        "xss_count": r["xss_count"],
        "scan_count": r["scan_count"],
        "bruteforce_count": r["bruteforce_count"],
        "exfiltration_count": r["exfiltration_count"],
        "file_attack_count": r["file_attack_count"],
        "admin_probe_count": r["admin_probe_count"],
        "sensitive_file_count": r["sensitive_file_count"],
        "command_injection_count": r["command_injection_count"]
    }
)

print("Ecriture global_protocol_stats...")
put_rows(
    tables["global_protocol_stats"],
    global_protocol_stats.collect(),
    lambda r: r["protocol"],
    lambda r: {
        "alert_count": r["alert_count"],
        "malicious_count": r["malicious_count"],
        "suspicious_count": r["suspicious_count"],
        "blocked_count": r["blocked_count"],
        "sqli_count": r["sqli_count"],
        "xss_count": r["xss_count"],
        "scan_count": r["scan_count"],
        "bruteforce_count": r["bruteforce_count"],
        "exfiltration_count": r["exfiltration_count"],
        "file_attack_count": r["file_attack_count"],
        "admin_probe_count": r["admin_probe_count"],
        "sensitive_file_count": r["sensitive_file_count"],
        "command_injection_count": r["command_injection_count"],
        "total_bytes": r["total_bytes"],
        "avg_bytes_per_alert": r["avg_bytes_per_alert"]
    }
)

print("Ecriture global_attack_patterns...")
put_rows(
    tables["global_attack_patterns"],
    global_attack_patterns.collect(),
    lambda r: r["alert_type"],
    lambda r: {
        "alert_count": r["alert_count"],
        "attack_category": r["attack_category"],
        "unique_attackers": r["unique_attackers"],
        "unique_targets": r["unique_targets"],
        "total_bytes": r["total_bytes"],
        "last_seen": r["last_seen"],
        "last_archived_at": r["last_archived_at"]
    }
)

print("Ecriture target_ip_stats...")
put_rows(
    tables["target_ip_stats"],
    target_ip_stats.collect(),
    lambda r: r["dest_ip"],
    lambda r: {
        "alert_count": r["alert_count"],
        "unique_attackers": r["unique_attackers"],
        "unique_protocols": r["unique_protocols"],
        "malicious_count": r["malicious_count"],
        "suspicious_count": r["suspicious_count"],
        "sqli_count": r["sqli_count"],
        "xss_count": r["xss_count"],
        "scan_count": r["scan_count"],
        "exfiltration_count": r["exfiltration_count"],
        "file_attack_count": r["file_attack_count"],
        "admin_probe_count": r["admin_probe_count"],
        "sensitive_file_count": r["sensitive_file_count"],
        "command_injection_count": r["command_injection_count"],
        "total_bytes": r["total_bytes"],
        "last_seen": r["last_seen"],
        "last_archived_at": r["last_archived_at"],
        "target_risk_score": r["target_risk_score"]
    }
)

print("Ecriture KPI total_unique_targets dans target_ip_stats...")
tables["target_ip_stats"].put(
    b"__KPI_TOTAL__",
    {
        b"cf:row_type": b"kpi",
        b"cf:total_unique_targets": str(total_unique_targets).encode()
    }
)

print("Ecriture threat_timeline...")
put_rows(
    tables["threat_timeline"],
    threat_timeline.collect(),
    lambda r: r["time_bucket"],
    lambda r: {
        "total_alerts": r["total_alerts"],
        "malicious_count": r["malicious_count"],
        "suspicious_count": r["suspicious_count"],
        "sqli_count": r["sqli_count"],
        "xss_count": r["xss_count"],
        "scan_count": r["scan_count"],
        "bruteforce_count": r["bruteforce_count"],
        "exfiltration_count": r["exfiltration_count"],
        "file_attack_count": r["file_attack_count"],
        "admin_probe_count": r["admin_probe_count"],
        "sensitive_file_count": r["sensitive_file_count"],
        "command_injection_count": r["command_injection_count"],
        "unique_attackers": r["unique_attackers"],
        "unique_targets": r["unique_targets"]
    }
)

print("Ecriture attacker_victim_stats...")
put_rows(
    tables["attacker_victim_stats"],
    attacker_victim_stats.collect(),
    lambda r: r["src_ip"] + "|" + r["dest_ip"],
    lambda r: {
        "src_ip": r["src_ip"],
        "dest_ip": r["dest_ip"],
        "alert_count": r["alert_count"],
        "unique_protocols": r["unique_protocols"],
        "malicious_count": r["malicious_count"],
        "suspicious_count": r["suspicious_count"],
        "sqli_count": r["sqli_count"],
        "xss_count": r["xss_count"],
        "scan_count": r["scan_count"],
        "exfiltration_count": r["exfiltration_count"],
        "file_attack_count": r["file_attack_count"],
        "admin_probe_count": r["admin_probe_count"],
        "sensitive_file_count": r["sensitive_file_count"],
        "command_injection_count": r["command_injection_count"],
        "total_bytes": r["total_bytes"],
        "last_seen": r["last_seen"],
        "last_archived_at": r["last_archived_at"],
        "relation_risk_score": r["relation_risk_score"]
    }
)

print("Ecriture ip_attack_types...")
put_rows(
    tables["ip_attack_types"],
    ip_attack_types.collect(),
    lambda r: r["src_ip"] + "|" + r["alert_type"],
    lambda r: {
        "src_ip": r["src_ip"],
        "alert_type": r["alert_type"],
        "category": r["attack_category"],
        "alert_count": r["alert_count"],
        "unique_targets": r["unique_targets"],
        "unique_protocols": r["unique_protocols"],
        "total_bytes": r["total_bytes"],
        "last_seen": r["last_seen"],
        "last_archived_at": r["last_archived_at"]
    }
)

print("Ecriture ip_historical_alerts...")
put_rows(
    tables["ip_historical_alerts"],
    ip_historical_alerts.collect(),
    lambda r: str(r["src_ip"]) + "|" + str(r["archived_at"]) + "|" + str(r["event_time"]) + "|" + str(r["row_hash"]),
    lambda r: {
        "src_ip": r["src_ip"],
        "dest_ip": r["dest_ip"],
        "protocol": r["protocol"],
        "path": r["path"],
        "alert_type": r["alert_type"],
        "attack_category": r["attack_category"],
        "event_time": r["event_time"],
        "archived_at": r["archived_at"],
        "bytes_transferred": r["bytes_transferred"]
    }
)

print("Ecriture high_risk_ips...")
put_rows(
    tables["high_risk_ips"],
    high_risk_ips.collect(),
    lambda r: r["src_ip"],
    lambda r: {
        "total_alerts": r["total_alerts"],
        "malicious_count": r["malicious_count"],
        "suspicious_count": r["suspicious_count"],
        "blocked_count": r["blocked_count"],
        "sqli_count": r["sqli_count"],
        "xss_count": r["xss_count"],
        "scan_count": r["scan_count"],
        "bruteforce_count": r["bruteforce_count"],
        "exfiltration_count": r["exfiltration_count"],
        "file_attack_count": r["file_attack_count"],
        "admin_probe_count": r["admin_probe_count"],
        "sensitive_file_count": r["sensitive_file_count"],
        "command_injection_count": r["command_injection_count"],
        "unique_targets": r["unique_targets"],
        "risk_score": r["risk_score"],
        "risk_level": r["risk_level"],
        "last_seen": r["last_seen"],
        "last_archived_at": r["last_archived_at"]
    }
)

connection.close()
spark.stop()

print("Batch global enrichi termine avec succes.")
