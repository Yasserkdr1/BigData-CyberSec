# 04 — Arrêt, reset et fermeture

Le script `stop_reset_close_all.ps1` permet d'arrêter les jobs, nettoyer les données de travail, réinitialiser les vues et fermer les services.

## 1. Lancer l'arrêt complet

Depuis le dossier contenant `stop_reset_close_all.ps1` :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\stop_reset_close_all.ps1
```

## 2. Ce que fait le script

- arrête les jobs Spark/Python ;
- tue les applications YARN restantes ;
- nettoie HDFS : `/data/cybersecurity/logs`, `/tmp/checkpoints`, `/tmp/spark-checkpoints` ;
- recrée les tables HBase utilisées par le batch ;
- vide la table Cassandra `cybersec.realtime_alerts_live` ;
- supprime puis recrée le topic Kafka `cybersecurity-logs` ;
- nettoie les logs locaux ;
- ferme HBase Thrift, HBase, Kafka/Zookeeper et Hadoop.

## 3. Commandes de contrôle après arrêt

Vérifier les processus sur le master :

```powershell
docker exec hadoop-master bash -lc "jps"
```

Vérifier les jobs restants :

```powershell
docker exec hadoop-master bash -lc "ps -ef | grep -E 'streaming.py|spark-submit|Kafka|HMaster|NameNode|Thrift' | grep -v grep || true"
docker exec hadoop-worker5 bash -lc "ps -ef | grep -E 'batch_loop.sh|batch_f.py|spark-submit' | grep -v grep || true"
```

## 4. Reset manuel rapide des vues HBase

À utiliser seulement si nécessaire :

```powershell
docker exec hadoop-master bash -lc "echo 'list' | hbase shell -n"
```

Vérifier une table :

```powershell
docker exec hadoop-master bash -lc "echo \"scan 'ip_reputation', {LIMIT => 5}\" | hbase shell -n"
```

Vérifier la ligne KPI des cibles, si elle est utilisée :

```powershell
docker exec hadoop-master bash -lc "echo \"get 'target_ip_stats', '__KPI_TOTAL__'\" | hbase shell -n"
```
