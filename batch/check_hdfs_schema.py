from pyspark.sql import SparkSession

spark = SparkSession.builder \
    .appName("CheckHDFSSchema") \
    .master("local[*]") \
    .getOrCreate()

df = spark.read.parquet("hdfs://hadoop-master:9000/data/cybersecurity/logs")

print("=== SCHEMA ===")
df.printSchema()

print("=== SAMPLE ===")
df.select("timestamp", "event_time", "archived_at").show(10, False)

spark.stop()