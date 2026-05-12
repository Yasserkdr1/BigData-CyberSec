# 03 — Starting the Pipeline

The `start_all.ps1` / `start.sh` script starts the services and launches the jobs. It does not create tables, topics, or keyspaces: initialization must already be done.

## 1. Verify the Containers

```bash
docker ps
```

Check that the containers used by the scripts are active:

- `hadoop-master`
- `hadoop-worker3`
- `hadoop-worker5`
- `cassandra`

## 2. Launch the Startup Script

**Linux / macOS / WSL:**

```bash
chmod +x starting/start.sh
./starting/start.sh
```

**Windows PowerShell:**

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\starting\start_all.ps1
```

The script will prompt for the duration between batch executions. Example:

```text
100
```

Depending on the current configuration, the batch loop first waits for the chosen interval, then executes the batch, then repeats.

## 3. Verify the Services

HDFS:

```bash
docker exec hadoop-master bash -lc "hdfs dfsadmin -report"
```

YARN:

```bash
docker exec hadoop-master bash -lc "yarn node -list"
```

Kafka:

```bash
docker exec hadoop-master bash -lc "kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic cybersecurity-logs"
```

HBase:

```bash
docker exec hadoop-master bash -lc "echo 'status' | hbase shell -n"
```

Thrift:

```bash
docker exec hadoop-master bash -lc "jps | grep -E 'Thrift|HMaster|HRegionServer'"
```

## 4. Verify the Jobs

Streaming:

```bash
docker exec hadoop-master bash -lc "ps -ef | grep -E 'streaming.py|spark-submit' | grep -v grep"
docker exec -it hadoop-master bash -lc "tail -f /root/streaming.log"
```

Batch on `hadoop-worker5`:

```bash
docker exec hadoop-worker5 bash -lc "ps -ef | grep -E 'batch_loop.sh|batch_f.py|spark-submit' | grep -v grep"
docker exec -it hadoop-worker5 bash -lc "tail -f /root/batch_global_final.log"
```

HDFS Archival on `hadoop-worker3`:

```bash
docker exec hadoop-worker3 bash -lc "ps -ef | grep -E 'archive_to_hdfs.py|spark-submit' | grep -v grep"
docker exec -it hadoop-worker3 bash -lc "tail -f /root/archive_to_hdfs.log"
```

## 5. Execute the Batch Once (Single Run)

```bash
docker exec -d hadoop-worker5 bash -lc "nohup spark-submit --master local[*] /root/batch_f.py > /root/batch_global_final_once.log 2>&1"
```

Follow the log:

```bash
docker exec -it hadoop-worker5 bash -lc "tail -f /root/batch_global_final_once.log"
```
