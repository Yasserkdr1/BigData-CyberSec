from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, lower, when, count, window,
    lit, to_timestamp, sum as spark_sum
)
from pyspark.sql.types import StructType, StringType, IntegerType

KAFKA_BROKER = "hadoop-master:9092"
KAFKA_TOPIC = "cybersecurity-logs"

spark = SparkSession.builder \
    .appName("CyberThreatStreamingConsole") \
    .config("spark.sql.shuffle.partitions", "4") \
    .getOrCreate()

spark.sparkContext.setLogLevel("WARN")

schema = StructType() \
    .add("timestamp", StringType()) \
    .add("source_ip", StringType()) \
    .add("dest_ip", StringType()) \
    .add("protocol", StringType()) \
    .add("action", StringType()) \
    .add("threat_label", StringType()) \
    .add("log_type", StringType()) \
    .add("bytes_transferred", IntegerType()) \
    .add("user_agent", StringType()) \
    .add("request_path", StringType())

raw_df = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", KAFKA_BROKER) \
    .option("subscribe", KAFKA_TOPIC) \
    .option("startingOffsets", "latest") \
    .load()

parsed_df = raw_df.selectExpr(
    "CAST(key AS STRING) as kafka_key",
    "CAST(value AS STRING) as json_value"
).select(
    col("kafka_key"),
    from_json(col("json_value"), schema).alias("data")
).select("kafka_key", "data.*")

stream_df = parsed_df.withColumn("event_time", to_timestamp(col("timestamp")))

ua = lower(col("user_agent"))
path = lower(col("request_path"))
action_col = lower(col("action"))

# 1. Alertes instantanées
instant_alerts = stream_df.withColumn(
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
    col("dest_ip").alias("dest_ip"),
    col("request_path").alias("path"),
    col("alert_type"),
    lit(None).cast("int").alias("count_value"),
    col("event_time")
)

# 2. Alertes Brute Force (AVEC FENÊTRE GLISSANTE)
bruteforce_alerts = stream_df.filter(
    (action_col == "blocked") & (path.contains("/login") | path.contains("/admin"))
).withWatermark("event_time", "2 minutes") \
 .groupBy(window(col("event_time"), "1 minute", "10 seconds"), col("source_ip")) \
 .agg(count("*").alias("failed_attempts")) \
 .filter(col("failed_attempts") >= 5) \
 .select(
    col("source_ip").alias("src_ip"), lit("-").alias("dest_ip"),
    lit("/login_or_admin").alias("path"), lit("BRUTE_FORCE").alias("alert_type"),
    col("failed_attempts").cast("int").alias("count_value"), col("window.end").alias("event_time")
)

all_alerts = instant_alerts.unionByName(bruteforce_alerts, allowMissingColumns=True)

# ---------------------------------------------------------
# NOUVELLE ÉCRITURE : AFFICHAGE DANS LA CONSOLE (SANS CASSANDRA)
# ---------------------------------------------------------
def afficher_sans_doublons(df, epoch_id):
    # Optimisation : on garde le micro-batch en mémoire le temps du traitement
    df.persist()
    
    # On supprime les doublons d'affichage
    df_clean = df.dropDuplicates(["src_ip", "alert_type"])
    
    # S'il y a des données, on affiche
    if df_clean.count() > 0:
        print(f"\n🚨 ALERTES DETECTÉES (Batch {epoch_id}) 🚨")
        df_clean.show(truncate=False)
        
    df.unpersist()

query = all_alerts.writeStream \
    .foreachBatch(afficher_sans_doublons) \
    .outputMode("append") \
    .trigger(processingTime="2 seconds") \
    .start()

query.awaitTermination()