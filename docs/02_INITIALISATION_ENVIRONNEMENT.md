# 02 — Initialisation de l'environnement

Cette étape se fait au premier lancement, ou après un reset complet. Elle prépare HDFS, Kafka, Cassandra et HBase.

## 1. Démarrer les conteneurs

Depuis le dossier contenant `docker-compose.yaml` :

```powershell
docker compose up -d
```

Vérifier :

```powershell
docker ps
```

Les conteneurs attendus pour ce projet sont notamment :

- `hadoop-master`
- `hadoop-worker3`
- `hadoop-worker5`
- `cassandra`

Si ton `docker-compose.yaml` ne contient que `hadoop-master`, `hadoop-worker1` et `hadoop-worker2`, ajoute aussi les workers utilisés par tes scripts ou adapte les noms dans les scripts PowerShell.

## 2. Démarrer les services une première fois

```powershell
docker exec hadoop-master bash -lc "/root/start-hadoop.sh"
docker exec hadoop-master bash -lc "/root/start-kafka-zookeeper.sh"
docker exec hadoop-master bash -lc "start-hbase.sh"
```

HBase peut prendre du temps. Attendre environ 60 secondes, puis vérifier :

```powershell
docker exec hadoop-master bash -lc "echo 'status' | hbase shell -n"
```

Démarrer Thrift :

```powershell
docker exec -d hadoop-master bash -lc "nohup hbase thrift start > /root/hbase-thrift.log 2>&1"
```

## 3. Initialiser HDFS

```powershell
docker exec hadoop-master bash -lc "hdfs dfsadmin -safemode leave || true"
docker exec hadoop-master bash -lc "hdfs dfs -mkdir -p /data/cybersecurity/logs"
docker exec hadoop-master bash -lc "hdfs dfs -mkdir -p /tmp/checkpoints"
docker exec hadoop-master bash -lc "hdfs dfs -mkdir -p /tmp/spark-checkpoints"
```

Vérifier :

```powershell
docker exec hadoop-master bash -lc "hdfs dfs -ls /data/cybersecurity"
```

## 4. Créer le topic Kafka

```powershell
docker exec hadoop-master bash -lc "kafka-topics.sh --bootstrap-server localhost:9092 --create --topic cybersecurity-logs --partitions 3 --replication-factor 1 || true"
```

Vérifier :

```powershell
docker exec hadoop-master bash -lc "kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic cybersecurity-logs"
```

## 5. Créer le keyspace et la table Cassandra

```powershell
docker exec cassandra cqlsh -e "CREATE KEYSPACE IF NOT EXISTS cybersec WITH replication = {'class':'SimpleStrategy','replication_factor':1};"
```

```powershell
docker exec cassandra cqlsh -e "USE cybersec; CREATE TABLE IF NOT EXISTS realtime_alerts_live (alert_date date, inserted_at timestamp, event_id uuid, source_ip text, dest_ip text, alert_type text, request_path text, count_value int, event_time timestamp, protocol text, user_agent text, PRIMARY KEY ((alert_date), inserted_at, event_id)) WITH CLUSTERING ORDER BY (inserted_at DESC, event_id DESC) AND default_time_to_live = 86400;"
```

Vérifier :

```powershell
docker exec cassandra cqlsh -e "USE cybersec; DESCRIBE TABLE realtime_alerts_live;"
```

## 6. Créer les tables HBase

Créer un fichier d'initialisation dans le conteneur puis l'exécuter :

```powershell
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

Si certaines tables existent déjà, utilise plutôt ton script de reset `stop_reset_close_all.ps1`, qui recrée les tables proprement.

Vérifier :

```powershell
docker exec hadoop-master bash -lc "echo 'list' | hbase shell -n"
```
