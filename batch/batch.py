from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, window, sum as spark_sum, countDistinct, desc
from pyspark.sql.types import StructType, StringType, IntegerType

# Initialization
spark = SparkSession.builder \
    .appName("CyberThreatBatchAnalysis") \
    .getOrCreate()

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

historical_logs = spark.read.schema(schema).csv("hdfs://localhost:9000/data/cybersecurity/logs/*/*/*")

top_ips = (historical_logs.filter(col("threat_label").isin("suspicious", "malicious"))
             .groupBy("source_ip")
             .count()
             .orderBy(desc("count"))
             .limit(10))

top_ips.show()