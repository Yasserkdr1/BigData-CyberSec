# 04 — Shutdown, Reset, and Cleanup

The `stop_reset_close_all.ps1` / `stop_reset.sh` script stops jobs, cleans working data, resets views, and shuts down services.

## 1. Launch the Full Shutdown

**Linux / macOS / WSL:**

```bash
chmod +x starting/stop_reset.sh
./starting/stop_reset.sh
```

**Windows PowerShell:**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\starting\stop_reset_close_all.ps1
```

## 2. What the Script Does

- Stops Spark/Python jobs
- Kills remaining YARN applications
- Cleans HDFS: `/data/cybersecurity/logs`, `/tmp/checkpoints`, `/tmp/spark-checkpoints`
- Drops and recreates HBase tables used by the batch layer
- Truncates the Cassandra table `cybersec.realtime_alerts_live`
- Deletes and recreates the Kafka topic `cybersecurity-logs`
- Cleans local logs
- Shuts down HBase Thrift, HBase, Kafka/Zookeeper, and Hadoop

## 3. Control Commands After Shutdown

Verify processes on the master:

```bash
docker exec hadoop-master bash -lc "jps"
```

Check for remaining jobs:

```bash
docker exec hadoop-master bash -lc "ps -ef | grep -E 'streaming.py|spark-submit|Kafka|HMaster|NameNode|Thrift' | grep -v grep || true"
docker exec hadoop-worker5 bash -lc "ps -ef | grep -E 'batch_loop.sh|batch_f.py|spark-submit' | grep -v grep || true"
```

## 4. Quick Manual Reset of HBase Views

Use only if needed:

```bash
docker exec hadoop-master bash -lc "echo 'list' | hbase shell -n"
```

Check a table:

```bash
docker exec hadoop-master bash -lc "echo \"scan 'ip_reputation', {LIMIT => 5}\" | hbase shell -n"
```

Check the KPI row for targets, if used:

```bash
docker exec hadoop-master bash -lc "echo \"get 'target_ip_stats', '__KPI_TOTAL__'\" | hbase shell -n"
```
