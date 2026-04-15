from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, lower, when, count, lit,
    sum as spark_sum
)
import happybase

HDFS_PATH = "hdfs://hadoop-master:9000/data/cybersecurity/logs"
HBASE_HOST = "hadoop-master"
HBASE_PORT = 9090

spark = SparkSession.builder \
    .appName("GlobalThreatStatsToHBase") \
    .master("local[*]") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

df = spark.read.parquet(HDFS_PATH)

ua = lower(col("user_agent"))
path = lower(col("request_path"))
action_col = lower(col("action"))

print("=== TOTAL LOGS GLOBAL ===")
print(df.count())

# 1) Alertes instantanées basées sur signatures
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
    col("protocol"),
    col("alert_type")
)

# 2) Activité bloquée répétée globale
bruteforce_candidates = df.filter(action_col == "blocked")

bruteforce_alerts = bruteforce_candidates \
    .groupBy(
        col("source_ip"),
        col("protocol")
    ) \
    .agg(count("*").alias("failed_attempts")) \
    .filter(col("failed_attempts") >= 5) \
    .select(
        col("source_ip").alias("src_ip"),
        col("protocol"),
        lit("REPEATED_BLOCKED_ACTIVITY").alias("alert_type")
    )

# 3) Volume anormal global
volume_alerts = df \
    .groupBy(col("source_ip"), col("protocol")) \
    .agg(spark_sum("bytes_transferred").alias("total_bytes")) \
    .filter(col("total_bytes") > 10 * 1024 * 1024) \
    .select(
        col("source_ip").alias("src_ip"),
        col("protocol"),
        lit("DATA_EXFILTRATION").alias("alert_type")
    )

all_alerts = instant_alerts.unionByName(bruteforce_alerts).unionByName(volume_alerts)

# Agrégations globales
ip_stats = all_alerts.groupBy("src_ip") \
    .count() \
    .orderBy(col("count").desc())

protocol_stats = all_alerts.groupBy("protocol") \
    .count() \
    .orderBy(col("count").desc())

pattern_stats = all_alerts.groupBy("alert_type") \
    .count() \
    .orderBy(col("count").desc())

# Collecte côté Python
ip_rows = ip_stats.collect()
protocol_rows = protocol_stats.collect()
pattern_rows = pattern_stats.collect()

print("Global IP rows:", len(ip_rows))
print("Global protocol rows:", len(protocol_rows))
print("Global pattern rows:", len(pattern_rows))

# Connexion HBase
connection = happybase.Connection(HBASE_HOST, port=HBASE_PORT)
connection.open()

global_ip_table = connection.table("global_ip_stats")
global_protocol_table = connection.table("global_protocol_stats")
global_pattern_table = connection.table("global_attack_patterns")

# Vider les anciennes lignes
for key, _ in global_ip_table.scan():
    global_ip_table.delete(key)

for key, _ in global_protocol_table.scan():
    global_protocol_table.delete(key)

for key, _ in global_pattern_table.scan():
    global_pattern_table.delete(key)

# Réécrire la vue globale
for row in ip_rows:
    global_ip_table.put(
        str(row["src_ip"]).encode(),
        {b"cf:alert_count": str(row["count"]).encode()}
    )

for row in protocol_rows:
    global_protocol_table.put(
        str(row["protocol"]).encode(),
        {b"cf:alert_count": str(row["count"]).encode()}
    )

for row in pattern_rows:
    global_pattern_table.put(
        str(row["alert_type"]).encode(),
        {b"cf:alert_count": str(row["count"]).encode()}
    )

connection.close()
spark.stop()

print("Ecriture des stats globales dans HBase OK")