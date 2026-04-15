from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, to_timestamp, year, month, dayofmonth, hour,
    current_timestamp
)
from pyspark.sql.types import StructType, StringType, IntegerType

KAFKA_BROKER = "hadoop-master:9092"
KAFKA_TOPIC = "cybersecurity-logs"

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

spark = SparkSession.builder \
    .appName("KafkaToHDFSArchive") \
    .getOrCreate()

spark.sparkContext.setLogLevel("ERROR")

raw_df = spark.readStream \
    .format("kafka") \
    .option("kafka.bootstrap.servers", KAFKA_BROKER) \
    .option("subscribe", KAFKA_TOPIC) \
    .option("startingOffsets", "latest") \
    .load()

parsed_df = raw_df.selectExpr("CAST(value AS STRING) as json_value") \
    .select(from_json(col("json_value"), schema).alias("data")) \
    .select("data.*")

df = parsed_df \
    .withColumn("event_time", to_timestamp(col("timestamp"))) \
    .withColumn("archived_at", current_timestamp()) \
    .withColumn("year", year(col("event_time"))) \
    .withColumn("month", month(col("event_time"))) \
    .withColumn("day", dayofmonth(col("event_time"))) \
    .withColumn("hour", hour(col("event_time")))

query = df.writeStream \
    .format("parquet") \
    .option("path", "hdfs://hadoop-master:9000/data/cybersecurity/logs") \
    .option("checkpointLocation", "hdfs://hadoop-master:9000/tmp/checkpoints/kafka-to-hdfs") \
    .partitionBy("year", "month", "day", "hour") \
    .outputMode("append") \
    .trigger(processingTime="1 minute") \
    .start()

query.awaitTermination()