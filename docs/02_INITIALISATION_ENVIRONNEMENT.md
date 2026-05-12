# 02 — Environment Initialization

This step is performed on the first launch, or after a full reset. It prepares HDFS, Kafka, Cassandra, and HBase.

## 1. Start the Containers

From the folder containing `docker-compose.yaml`:

```bash
docker compose up -d
```

Verify:

```bash
docker ps
```

The expected containers for this project include:

- `hadoop-master`
- `hadoop-worker3`
- `hadoop-worker5`
- `cassandra`

If your `docker-compose.yaml` only contains `hadoop-master`, `hadoop-worker1`, and `hadoop-worker2`, also add the workers used by your scripts or adapt the names in the PowerShell/Bash scripts.

## 2. Start the Services for the First Time

```bash
docker exec hadoop-master bash -lc "/root/start-hadoop.sh"
docker exec hadoop-master bash -lc "/root/start-kafka-zookeeper.sh"
docker exec hadoop-master bash -lc "start-hbase.sh"
```

HBase can take a while. Wait approximately 60 seconds, then verify:

```bash
docker exec hadoop-master bash -lc "echo 'status' | hbase shell -n"
```

Start Thrift:

```bash
docker exec -d hadoop-master bash -lc "nohup hbase thrift start > /root/hbase-thrift.log 2>&1"
```

## 3. Initialize HDFS

```bash
docker exec hadoop-master bash -lc "hdfs dfsadmin -safemode leave || true"
docker exec hadoop-master bash -lc "hdfs dfs -mkdir -p /data/cybersecurity/logs"
docker exec hadoop-master bash -lc "hdfs dfs -mkdir -p /tmp/checkpoints"
docker exec hadoop-master bash -lc "hdfs dfs -mkdir -p /tmp/spark-checkpoints"
```

Verify:

```bash
docker exec hadoop-master bash -lc "hdfs dfs -ls /data/cybersecurity"
```

## 4. Create the Kafka Topic

```bash
docker exec hadoop-master bash -lc "kafka-topics.sh --bootstrap-server localhost:9092 --create --topic cybersecurity-logs --partitions 3 --replication-factor 1 || true"
```

Verify:

```bash
docker exec hadoop-master bash -lc "kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic cybersecurity-logs"
```

## 5. Create the Cassandra Keyspace and Table

```bash
docker exec cassandra cqlsh -e "CREATE KEYSPACE IF NOT EXISTS cybersec WITH replication = {'class':'SimpleStrategy','replication_factor':1};"
```

```bash
docker exec cassandra cqlsh -e "USE cybersec; CREATE TABLE IF NOT EXISTS realtime_alerts_live (alert_date date, inserted_at timestamp, event_id uuid, source_ip text, dest_ip text, alert_type text, request_path text, count_value int, event_time timestamp, protocol text, user_agent text, PRIMARY KEY ((alert_date), inserted_at, event_id)) WITH CLUSTERING ORDER BY (inserted_at DESC, event_id DESC) AND default_time_to_live = 86400;"
```

Verify:

```bash
docker exec cassandra cqlsh -e "USE cybersec; DESCRIBE TABLE realtime_alerts_live;"
```

## 6. Create HBase Tables

Create an initialization file in the container, then execute it:

```bash
docker exec hadoop-master bash -lc "cat > /tmp/init_hbase_tables.hb <<'EOF'
create 'global_ip_stats', 'cf'
create 'global_protocol_stats', 'cf'
create 'global_attack_patterns', 'cf'
create 'ip_reputation', 'cf'
create 'target_ip_stats', 'cf'
create 'threat_timeline', 'cf'
create 'attacker_victim_stats', 'cf'
create 'high_risk_ips', 'cf'
create 'ip_attack_types', 'cf'
create 'ip_historical_alerts', 'cf'
list
EOF
hbase shell -n /tmp/init_hbase_tables.hb"
```

If some tables already exist, use the reset script `stop_reset_close_all.ps1` or `stop_reset.sh` instead, which recreates the tables cleanly.

Verify:

```bash
docker exec hadoop-master bash -lc "echo 'list' | hbase shell -n"
```
