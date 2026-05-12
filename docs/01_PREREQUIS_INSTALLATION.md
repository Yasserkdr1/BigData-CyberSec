# 01 — Prerequisites and Required Installations

This file describes what must be available before launching the cluster and jobs.

## 1. On the Windows Machine

Install:

- Docker Desktop
- PowerShell
- A code editor, e.g. VS Code

Verify Docker:

```powershell
docker --version
docker compose version
```

Temporarily allow PowerShell script execution:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## 2. Inside `hadoop-master`

The `hadoop-master` container must contain:

- Hadoop / HDFS / YARN
- Spark
- Kafka and Zookeeper
- HBase
- HBase Thrift Server
- The commands: `start-hadoop.sh`, `start-kafka-zookeeper.sh`, `start-hbase.sh`, `stop-hadoop.sh`, `stop-hbase.sh`
- The required Python files, notably:
  - `/root/streaming.py`
  - `/root/archive_to_hdfs.py` if used on the master

Useful Python packages on the master:

```bash
pip install cassandra-driver happybase thriftpy2
```

## 3. Inside `hadoop-worker5`

This worker runs the batch job. It must contain:

- Spark
- Python 3
- The file `/root/batch_f.py`
- The Python HBase driver to write to HBase via Thrift

Minimal installation:

```bash
pip install happybase thriftpy2
```

## 4. Inside `hadoop-worker3`

This worker runs the Kafka-to-HDFS archival job. It must contain:

- Spark
- Python 3
- The file `/root/archive_to_hdfs.py`

## 5. On Spark/YARN Workers

Since streaming can be executed via YARN, the workers running Spark tasks must have the Python dependencies used by the job:

```bash
pip install cassandra-driver
```

## 6. Cassandra

The Cassandra container must be started and accessible on the Docker network. It must contain the keyspace and table used by streaming, created during the initialization step.
