from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, window, sum as spark_sum, countDistinct, desc, when, avg, max as spark_max
from pyspark.sql.types import StructType, StringType, IntegerType
import happybase #for Hbase

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


#1. filtering logs and identifying top source IPs

historical_logs = spark.read.schema(schema).option("header", "true").csv("hdfs://localhost:9000/data/cybersecurity/logs/*/*/*")

top_ips = (historical_logs.filter(col("threat_label").isin("suspicious", "malicious"))
             .groupBy("source_ip")
             .count()
             .orderBy(desc("count"))
             .limit(10))

top_ips.show()



#2. identifying potential scanning activities (multiple destination IPs from same source in short time)

scans = (historical_logs.filter(col("protocol") == "TCP")
         .groupBy(window(col("timestamp"), "5 minutes"), "source_ip")
         .agg(countDistinct("dest_ip").alias("targeted_hosts"))
         .filter(col("targeted_hosts") > 5)
         .orderBy(desc("targeted_hosts")))


scans.show()


#3. Analyzing SQLi/XSS patterns
path=col("request_path")
attack_analysis = historical_logs.withColumn("attack_type",
    when(path.rlike(r"(?i)\bor\b\s+1=1"), "SQLI_TAUTOLOGY")
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
    .otherwise("Other/normal"))

only_attacks = attack_analysis.filter(col("attack_type") != "Other/normal")
attack_pattern_counts = only_attacks.groupBy("attack_type").agg(count("*").alias("total_occurrences"))\
    .orderBy(col("total_occurrences").desc())

attack_pattern_counts.show()



#4. Amount of data transferred in malicious vs non-malicious logs

threat_volume_analysis = historical_logs.groupBy("threat_label") \
    .agg(
        spark_sum("bytes_transferred").alias("total_bytes"),
        
        avg("bytes_transferred").alias("avg_bytes_per_request"),
        
        spark_max("bytes_transferred").alias("max_single_transfer"),
        
        count("*").alias("total_requests")
    ) \
    .orderBy(col("total_bytes").desc())

threat_volume_analysis.show(truncate=False)





#5. writing results to HDFS(HBase)
#note: must downgrade/use to python 3.10 becasue of compatibility



def write_to_hbase(table_name,column_family="info"):
    def process_partition(partition):
        import happybase #for Hbase
        connection = happybase.Connection('localhost', port=9090)
        table = connection.table(table_name)
       
        for row in partition:
            row_dict=row.asDict()
            first_col_name=list(row_dict.keys())[0]
            row_key=str(row_dict[first_col_name]).encode('utf-8')

            data={}
            for col_name, val in row_dict.items():
                if col_name != first_col_name and val is not None: #skipping first column
                    data[f"{column_family}:{col_name}".encode('utf-8')] = str(val).encode('utf-8')
            table.put(row_key, data)
        connection.close()  
    return process_partition

#testing Hbase
top_ips.foreachPartition(write_to_hbase("ip_reputation"))