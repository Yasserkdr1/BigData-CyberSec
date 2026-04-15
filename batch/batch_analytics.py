from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lower, when, count, sum as spark_sum, to_date

spark = SparkSession.builder \
    .appName("CyberBatchAnalytics") \
    .getOrCreate()

df = spark.read.parquet("hdfs://hadoop-master:9000/data/cybersecurity/logs")

# 1) Top IPs malveillantes
top_ips = df.filter(col("threat_label").isin("suspicious", "malicious")) \
    .groupBy("source_ip") \
    .count() \
    .orderBy(col("count").desc()) \
    .limit(10)

print("=== TOP IPS MALVEILLANTES ===")
top_ips.show(truncate=False)

# 2) Patterns d'attaque
path_col = lower(col("request_path"))

patterns = df.withColumn(
    "attack_pattern",
    when(path_col.rlike(r"(?i)\bor\b\s+1=1"), "SQLI_TAUTOLOGY")
    .when(path_col.rlike(r"(?i)union\s+select"), "SQLI_UNION")
    .when(path_col.rlike(r"(?i)<script"), "XSS_SCRIPT")
    .when(path_col.rlike(r"(?i)onerror\\s*="), "XSS_ONERROR")
    .when(path_col.rlike(r"(?i)wp-login\\.php"), "WP_LOGIN")
    .when(path_col.rlike(r"(?i)phpmyadmin"), "PHPMYADMIN")
).filter(col("attack_pattern").isNotNull())

attack_patterns = patterns.groupBy("attack_pattern") \
    .count() \
    .orderBy(col("count").desc())

print("=== ATTACK PATTERNS ===")
attack_patterns.show(truncate=False)

# 3) Threat timeline
timeline = df.withColumn("event_date", to_date(col("event_time"))) \
    .groupBy("event_date", "threat_label") \
    .count() \
    .orderBy("event_date")

print("=== THREAT TIMELINE ===")
timeline.show(truncate=False)

# 4) Volume transféré par type de menace
volume_stats = df.groupBy("threat_label") \
    .agg(spark_sum("bytes_transferred").alias("total_bytes")) \
    .orderBy(col("total_bytes").desc())

print("=== VOLUME PAR MENACE ===")
volume_stats.show(truncate=False)

spark.stop()