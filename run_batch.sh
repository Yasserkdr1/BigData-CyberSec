#!/bin/bash


#script to automate running batch pipeline
# Exit immediately if a command exits with a non-zero status
set -e 

echo "🚀 Starting the Big Data Cybersecurity Batch Pipeline..."

# 1. Start Docker Compose (just in case it isn't running)
echo "📦 Ensuring Docker containers are running..."
docker compose up -d
sleep 5 # Give containers a moment to initialize

# 2. Start Hadoop
echo "🐘 Starting Hadoop inside the master node..."
docker exec hadoop-master bash -c "./start-hadoop.sh"

# 3. Start HBase & Thrift Server
echo "🗄️ Starting HBase Master..."
docker exec hadoop-master bash -c "start-hbase.sh"

echo "🔌 Starting HBase Thrift Server in the background..."
docker exec -d hadoop-master bash -c "hbase thrift start"

# 4. HDFS Setup & Data Ingestion
echo "📁 Creating HDFS directory structure..."
# Creating the partitioned directory structure requested in the project [cite: 41, 86]
docker exec hadoop-master hdfs dfs -mkdir -p /data/cybersecurity/logs/2023/10/15/

echo "📤 Uploading historical logs to HDFS..."
# Step A: Copy from your local machine into the Docker container's temporary folder
docker cp mini_Db_Logs.csv hadoop-master:/tmp/mini_Db_Logs.csv
# Step B: Put the file from the container into HDFS [cite: 43]
docker exec hadoop-master hdfs dfs -put -f /tmp/mini_Db_Logs.csv /data/cybersecurity/logs/2023/10/15/

# 5. Create HBase Tables
echo "🛠️ Creating HBase tables (this might take a few seconds to connect)..."
# We pipe the commands directly into the HBase shell silently
docker exec -i hadoop-master hbase shell <<EOF
create 'ip_reputation', 'info'
create 'attack_patterns', 'info'
create 'threat_timeline', 'info'
exit
EOF

#

echo "✅ Pipeline Complete! Now you can run batch.py with python 3.10"