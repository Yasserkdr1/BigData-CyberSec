from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, lower, when, count, window,
    lit, to_timestamp, coalesce, sum as spark_sum
)
from pyspark.sql.types import StructType, StringType, IntegerType

KAFKA_BROKER = "hadoop-master:9092"
KAFKA_TOPIC = "cybersecurity-logs"

CASSANDRA_HOST = "cassandra"
CASSANDRA_PORT = 9042
CASSANDRA_KEYSPACE = "cybersec"
CASSANDRA_TABLE = "realtime_alerts_live"
TTL_SECONDS = 86400

spark = SparkSession.builder \
    .appName("CyberThreatStreamingFastWrite") \
    .config("spark.sql.shuffle.partitions", "4") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

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
    .option("maxOffsetsPerTrigger", 5000) \
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

bruteforce_candidates = stream_df.filter(
    (action_col == "blocked") &
    (
        path.contains("/login") |
        path.contains("/admin") |
        path.contains("/wp-login") |
        path.contains("/auth") |
        path.contains("/api/login")
    )
)

bruteforce_alerts = bruteforce_candidates \
    .withWatermark("event_time", "2 minutes") \
    .groupBy(window(col("event_time"), "1 minute"), col("source_ip")) \
    .agg(count("*").alias("failed_attempts")) \
    .filter(col("failed_attempts") >= 5) \
    .select(
        col("source_ip").alias("src_ip"),
        lit("-").alias("dest_ip"),
        lit("/login,/admin,/wp-login,/auth,/api/login").alias("path"),
        lit("BRUTE_FORCE").alias("alert_type"),
        col("failed_attempts").cast("int").alias("count_value"),
        col("window.end").alias("event_time")
    )

volume_alerts = stream_df \
    .withWatermark("event_time", "30 seconds") \
    .groupBy(window(col("event_time"), "10 seconds"), col("source_ip")) \
    .agg(spark_sum("bytes_transferred").alias("total_bytes")) \
    .filter(col("total_bytes") > 10 * 1024 * 1024) \
    .select(
        col("source_ip").alias("src_ip"),
        lit("-").alias("dest_ip"),
        lit("high-volume-transfer").alias("path"),
        lit("DATA_EXFILTRATION").alias("alert_type"),
        col("total_bytes").cast("int").alias("count_value"),
        col("window.end").alias("event_time")
    )

all_alerts = instant_alerts.unionByName(bruteforce_alerts).unionByName(volume_alerts)

def write_partition(rows):
    from cassandra.cluster import Cluster
    import uuid
    from datetime import datetime

    cluster = Cluster([CASSANDRA_HOST], port=CASSANDRA_PORT)
    session = cluster.connect(CASSANDRA_KEYSPACE)

    stmt = session.prepare(f"""
        INSERT INTO {CASSANDRA_TABLE}
        (alert_date, inserted_at, event_id, source_ip, dest_ip, alert_type, request_path, count_value, event_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """)

    futures = []

    for r in rows:
        inserted_at = datetime.utcnow()
        event_time = r.event_time if r.event_time is not None else inserted_at
        event_id = uuid.uuid1()

        futures.append(session.execute_async(stmt, (
            inserted_at.date(),
            inserted_at,
            event_id,
            r.src_ip,
            r.dest_ip if r.dest_ip is not None else "-",
            r.alert_type,
            r.path if r.path is not None else "-",
            int(r.count_value) if r.count_value is not None else None,
            event_time
        )))

    for f in futures:
        f.result()

    session.shutdown()
    cluster.shutdown()

def write_batch(batch_df, batch_id):
    if not batch_df.rdd.isEmpty():
        batch_df.foreachPartition(write_partition)

query = all_alerts.writeStream \
    .foreachBatch(write_batch) \
    .outputMode("append") \
    .trigger(processingTime="1 second") \
    .option("checkpointLocation", "/tmp/spark-checkpoints/realtime-alerts-fast") \
    .start()

query.awaitTermination()