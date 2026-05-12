# 03 — Démarrage du pipeline

Le script `start_all.ps1` démarre les services et lance les jobs. Il ne crée pas les tables, le topic ou le keyspace : l'initialisation doit déjà être faite.

## 1. Vérifier les conteneurs

```powershell
docker ps
```

Vérifier que les conteneurs utilisés par les scripts sont actifs :

- `hadoop-master`
- `hadoop-worker3`
- `hadoop-worker5`
- `cassandra`

## 2. Lancer le script de démarrage

Depuis le dossier contenant `start_all.ps1` :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\start_all.ps1
```

Le script demande la durée entre deux exécutions batch. Exemple :

```text
100
```

Selon la configuration actuelle, la boucle batch attend d'abord la durée choisie, puis exécute le batch, puis recommence.

## 3. Vérifier les services

HDFS :

```powershell
docker exec hadoop-master bash -lc "hdfs dfsadmin -report"
```

YARN :

```powershell
docker exec hadoop-master bash -lc "yarn node -list"
```

Kafka :

```powershell
docker exec hadoop-master bash -lc "kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic cybersecurity-logs"
```

HBase :

```powershell
docker exec hadoop-master bash -lc "echo 'status' | hbase shell -n"
```

Thrift :

```powershell
docker exec hadoop-master bash -lc "jps | grep -E 'Thrift|HMaster|HRegionServer'"
```

## 4. Vérifier les jobs

Streaming :

```powershell
docker exec hadoop-master bash -lc "ps -ef | grep -E 'streaming.py|spark-submit' | grep -v grep"
docker exec -it hadoop-master bash -lc "tail -f /root/streaming.log"
```

Batch sur `hadoop-worker5` :

```powershell
docker exec hadoop-worker5 bash -lc "ps -ef | grep -E 'batch_loop.sh|batch_f.py|spark-submit' | grep -v grep"
docker exec -it hadoop-worker5 bash -lc "tail -f /root/batch_global_final.log"
```

Archivage HDFS sur `hadoop-worker3` :

```powershell
docker exec hadoop-worker3 bash -lc "ps -ef | grep -E 'archive_to_hdfs.py|spark-submit' | grep -v grep"
docker exec -it hadoop-worker3 bash -lc "tail -f /root/archive_to_hdfs.log"
```

## 5. Exécuter le batch une seule fois

```powershell
docker exec -d hadoop-worker5 bash -lc "nohup spark-submit --master local[*] /root/batch_f.py > /root/batch_global_final_once.log 2>&1"
```

Suivre le log :

```powershell
docker exec -it hadoop-worker5 bash -lc "tail -f /root/batch_global_final_once.log"
```
