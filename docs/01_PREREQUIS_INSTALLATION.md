# 01 — Pré-requis et installations nécessaires

Ce fichier décrit ce qui doit être disponible avant le lancement du cluster et des jobs.

## 1. Côté machine Windows

Installer :

- Docker Desktop
- PowerShell
- un éditeur de code, par exemple VS Code

Vérifier Docker :

```powershell
docker --version
docker compose version
```

Autoriser temporairement l'exécution des scripts PowerShell :

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## 2. Côté `hadoop-master`

Le conteneur `hadoop-master` doit contenir :

- Hadoop / HDFS / YARN
- Spark
- Kafka et Zookeeper
- HBase
- HBase Thrift Server
- les commandes : `start-hadoop.sh`, `start-kafka-zookeeper.sh`, `start-hbase.sh`, `stop-hadoop.sh`, `stop-hbase.sh`
- les fichiers Python nécessaires, notamment :
  - `/root/streaming.py`
  - `/root/archive_to_hdfs.py` si utilisé sur le master

Packages Python utiles sur le master :

```bash
pip install cassandra-driver happybase thriftpy2
```

## 3. Côté `hadoop-worker5`

Ce worker exécute le job batch. Il doit contenir :

- Spark
- Python 3
- le fichier `/root/batch_f.py`
- le driver HBase Python pour écrire dans HBase via Thrift

Installation minimale :

```bash
pip install happybase thriftpy2
```

## 4. Côté `hadoop-worker3`

Ce worker exécute l'archivage Kafka vers HDFS. Il doit contenir :

- Spark
- Python 3
- le fichier `/root/archive_to_hdfs.py`

## 5. Côté workers Spark/YARN

Comme le streaming peut être exécuté via YARN, les workers qui exécutent les tâches Spark doivent avoir les dépendances Python utilisées par le job :

```bash
pip install cassandra-driver
```

## 6. Cassandra

Le conteneur Cassandra doit être démarré et accessible sur le réseau Docker. Il doit contenir le keyspace et la table utilisés par le streaming, créés dans l'étape d'initialisation.
