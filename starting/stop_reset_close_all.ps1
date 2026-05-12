# ============================================================
# STOP + FULL RESET + FERMETURE SERVICES CYBERSEC BIG DATA
# HDFS + HBase + Cassandra + Kafka
# ============================================================
# A executer depuis PowerShell Windows :
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   .\stop_reset_close_all.ps1
# ============================================================

$ErrorActionPreference = "Continue"

# =========================
# Configuration conteneurs
# =========================
$MASTER_CONTAINER     = "hadoop-master"
$ARCHIVE_CONTAINER    = "hadoop-worker3"
$BATCH_CONTAINER      = "hadoop-worker5"
$STREAM_CONTAINER     = "hadoop-master"
$CASSANDRA_CONTAINER  = "cassandra"

$KAFKA_TOPIC          = "cybersecurity-logs"
$KAFKA_PARTITIONS     = 3
$KAFKA_REPLICATION    = 1
$CASSANDRA_KEYSPACE   = "cybersec"
$CASSANDRA_TABLE      = "realtime_alerts_live"

function Step($msg) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $msg -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function DockerExec($container, $bashCmd) {
    Write-Host ""
    Write-Host ">> docker exec $container bash -lc `"$bashCmd`"" -ForegroundColor Yellow
    & docker exec $container bash -lc $bashCmd
}

function ContainerExists($name) {
    $result = docker ps -a --format "{{.Names}}" | Select-String -Pattern "^$name$"
    return $null -ne $result
}

function ContainerRunning($name) {
    $result = docker ps --format "{{.Names}}" | Select-String -Pattern "^$name$"
    return $null -ne $result
}

function CheckContainer($name) {
    if (-not (ContainerExists $name)) {
        Write-Host "ERREUR: conteneur introuvable: $name" -ForegroundColor Red
        exit 1
    }
    if (-not (ContainerRunning $name)) {
        Write-Host "ERREUR: conteneur non demarre: $name" -ForegroundColor Red
        Write-Host "Demarre tes conteneurs Docker avant ce script." -ForegroundColor Red
        exit 1
    }
}

# ============================================================
# 0. VERIFICATION CONTENEURS
# ============================================================
Step "0. Verification des conteneurs"
CheckContainer $MASTER_CONTAINER
CheckContainer $ARCHIVE_CONTAINER
CheckContainer $BATCH_CONTAINER
CheckContainer $STREAM_CONTAINER
CheckContainer $CASSANDRA_CONTAINER
Write-Host "Tous les conteneurs necessaires sont demarres." -ForegroundColor Green

# ============================================================
# 1. STOP DES JOBS SPARK / PYTHON
# ============================================================
Step "1. Arret des jobs Spark / Python"

DockerExec $ARCHIVE_CONTAINER "pkill -f archive_to_hdfs.py || true; pkill -f 'spark-submit.*archive_to_hdfs.py' || true"
DockerExec $BATCH_CONTAINER "pkill -f batch_loop.sh || true; pkill -f 'while true' || true; pkill -f '/root/batch_f.py' || true; pkill -f '/root/batch_global_final.py' || true; pkill -f 'spark-submit.*batch_f.py' || true; pkill -f 'spark-submit.*batch_global_final.py' || true"
DockerExec $STREAM_CONTAINER "pkill -f '/root/streaming.py' || true; pkill -f 'spark-submit.*streaming.py' || true"

Write-Host ""
Write-Host "Attente 5 secondes apres kill des jobs..." -ForegroundColor Magenta
Start-Sleep -Seconds 5

# ============================================================
# 2. KILL DES APPLICATIONS YARN RESTANTES
# ============================================================
Step "2. Kill des applications YARN restantes"
DockerExec $MASTER_CONTAINER "yarn application -list 2>/dev/null | awk '/application_/ {print \$1}' | xargs -r -n1 yarn application -kill || true"

Step "3. Verification processus jobs restants"
DockerExec $STREAM_CONTAINER "ps -ef | grep -E 'streaming.py|spark-submit' | grep -v grep || true"
DockerExec $BATCH_CONTAINER "ps -ef | grep -E 'batch_loop.sh|batch_f.py|batch_global_final.py|spark-submit|while true' | grep -v grep || true"
DockerExec $MASTER_CONTAINER "yarn application -list || true"

# ============================================================
# 4. RESET HDFS
# ============================================================
Step "4. Nettoyage HDFS"

DockerExec $MASTER_CONTAINER "hdfs dfsadmin -safemode leave || true"
DockerExec $MASTER_CONTAINER "hdfs dfs -rm -r -f /data/cybersecurity/logs || true"
DockerExec $MASTER_CONTAINER "hdfs dfs -rm -r -f /tmp/checkpoints || true"
DockerExec $MASTER_CONTAINER "hdfs dfs -rm -r -f /tmp/spark-checkpoints || true"
DockerExec $MASTER_CONTAINER "hdfs dfs -mkdir -p /data/cybersecurity/logs"
DockerExec $MASTER_CONTAINER "hdfs dfs -mkdir -p /tmp/checkpoints"
DockerExec $MASTER_CONTAINER "hdfs dfs -mkdir -p /tmp/spark-checkpoints"
DockerExec $MASTER_CONTAINER "hdfs dfs -ls /data/cybersecurity || true"
DockerExec $MASTER_CONTAINER "hdfs dfs -ls /tmp || true"

# ============================================================
# 5. RESET HBASE TABLES
# ============================================================
Step "5. Reset HBase : suppression et recreation des tables finales"

$hbaseScript = @"
def reset_table(t)
  if exists(t)
    disable t if is_enabled(t)
    drop t
  end
  create t, 'cf'
end

if exists('recent_ip_stats')
  disable 'recent_ip_stats' if is_enabled('recent_ip_stats')
  drop 'recent_ip_stats'
end

if exists('recent_protocol_stats')
  disable 'recent_protocol_stats' if is_enabled('recent_protocol_stats')
  drop 'recent_protocol_stats'
end

if exists('recent_attack_patterns')
  disable 'recent_attack_patterns' if is_enabled('recent_attack_patterns')
  drop 'recent_attack_patterns'
end

reset_table 'global_ip_stats'
reset_table 'global_protocol_stats'
reset_table 'global_attack_patterns'
reset_table 'ip_reputation'
reset_table 'target_ip_stats'
reset_table 'threat_timeline'
reset_table 'attacker_victim_stats'
reset_table 'high_risk_ips'
reset_table 'ip_attack_types'
reset_table 'ip_historical_alerts'

list
"@

$tempFile = Join-Path $env:TEMP "hbase_reset_final.hb"
$hbaseScript | Out-File -FilePath $tempFile -Encoding ascii

Write-Host ""
Write-Host ">> docker cp $tempFile ${MASTER_CONTAINER}:/tmp/hbase_reset_final.hb" -ForegroundColor Yellow
& docker cp $tempFile "${MASTER_CONTAINER}:/tmp/hbase_reset_final.hb"

DockerExec $MASTER_CONTAINER "hbase shell -n /tmp/hbase_reset_final.hb"
DockerExec $MASTER_CONTAINER "echo 'list' | hbase shell -n"

# ============================================================
# 6. VIDAGE CASSANDRA
# ============================================================
Step "6. Vidage Cassandra"
Write-Host ""
Write-Host ">> docker exec $CASSANDRA_CONTAINER cqlsh -e `"USE $CASSANDRA_KEYSPACE; TRUNCATE $CASSANDRA_TABLE;`"" -ForegroundColor Yellow
& docker exec $CASSANDRA_CONTAINER cqlsh -e "USE $CASSANDRA_KEYSPACE; TRUNCATE $CASSANDRA_TABLE;"

# Si tu as aussi une table realtime_alerts_by_ip, de-commente cette ligne :
# & docker exec $CASSANDRA_CONTAINER cqlsh -e "USE $CASSANDRA_KEYSPACE; TRUNCATE realtime_alerts_by_ip;"

# ============================================================
# 7. RESET KAFKA TOPIC
# ============================================================
Step "7. Reset Kafka topic $KAFKA_TOPIC"

DockerExec $MASTER_CONTAINER "kafka-topics.sh --bootstrap-server localhost:9092 --delete --topic $KAFKA_TOPIC || true"

Write-Host ""
Write-Host "Attente 5 secondes apres suppression du topic..." -ForegroundColor Magenta
Start-Sleep -Seconds 5

DockerExec $MASTER_CONTAINER "kafka-topics.sh --bootstrap-server localhost:9092 --create --topic $KAFKA_TOPIC --partitions $KAFKA_PARTITIONS --replication-factor $KAFKA_REPLICATION || true"

# ============================================================
# 8. NETTOYAGE LOGS LOCAUX
# ============================================================
Step "8. Nettoyage logs locaux des jobs"

DockerExec $ARCHIVE_CONTAINER "rm -f /root/archive_to_hdfs.log || true"
DockerExec $BATCH_CONTAINER "rm -f /root/batch_global_final.log /root/batch_global_final_loop.log /root/batch_f.log /root/batch_loop.sh || true"
DockerExec $STREAM_CONTAINER "rm -f /root/streaming.log /root/hbase-thrift.log || true"

# ============================================================
# 9. VERIFICATION FINALE AVANT FERMETURE SERVICES
# ============================================================
Step "9. Verification finale avant fermeture services"

DockerExec $MASTER_CONTAINER "hdfs dfs -ls -R /data/cybersecurity/logs || true"
DockerExec $MASTER_CONTAINER "echo \"scan 'ip_reputation', {LIMIT => 5}\" | hbase shell -n || true"
DockerExec $MASTER_CONTAINER "echo \"scan 'ip_historical_alerts', {LIMIT => 5}\" | hbase shell -n || true"

Write-Host ""
Write-Host ">> docker exec $CASSANDRA_CONTAINER cqlsh -e `"USE $CASSANDRA_KEYSPACE; SELECT COUNT(*) FROM $CASSANDRA_TABLE;`"" -ForegroundColor Yellow
& docker exec $CASSANDRA_CONTAINER cqlsh -e "USE $CASSANDRA_KEYSPACE; SELECT COUNT(*) FROM $CASSANDRA_TABLE;"

DockerExec $MASTER_CONTAINER "kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic $KAFKA_TOPIC || true"
DockerExec $MASTER_CONTAINER "yarn application -list || true"

# ============================================================
# 10. FERMETURE SERVICES
# Hadoop: stop-hadoop.sh
# HBase: stop-hbase.sh
# Thrift/Kafka/Zookeeper: kill/pkill
# ============================================================
Step "10. Fermeture des services"

Step "10.1 Stop HBase Thrift Server par kill/pkill"
DockerExec $MASTER_CONTAINER "pkill -f 'hbase.*thrift' || true; pkill -f 'ThriftServer' || true"

Step "10.2 Stop HBase avec stop-hbase.sh"
DockerExec $MASTER_CONTAINER "stop-hbase.sh || true"

Step "10.3 Stop Kafka et Zookeeper par kill/pkill"
DockerExec $MASTER_CONTAINER "pkill -f 'kafka.Kafka' || true; pkill -f 'Kafka' || true; pkill -f 'QuorumPeerMain' || true; pkill -f 'zookeeper' || true"

Step "10.4 Stop Hadoop avec /root/stop-hadoop.sh ou stop-hadoop.sh"
DockerExec $MASTER_CONTAINER "if [ -f /root/stop-hadoop.sh ]; then bash /root/stop-hadoop.sh; else stop-hadoop.sh || true; fi"

Write-Host ""
Write-Host "Attente 5 secondes apres fermeture services..." -ForegroundColor Magenta
Start-Sleep -Seconds 5

Step "11. Verification processus services restants"
DockerExec $MASTER_CONTAINER "jps || true"
DockerExec $MASTER_CONTAINER "ps -ef | grep -E 'NameNode|DataNode|ResourceManager|NodeManager|HMaster|HRegionServer|Kafka|QuorumPeerMain|zookeeper|ThriftServer' | grep -v grep || true"

Step "STOP + RESET + FERMETURE TERMINE"
Write-Host "Environnement nettoye et services fermes :" -ForegroundColor Green
Write-Host " - Jobs Spark/Python arretes" -ForegroundColor Green
Write-Host " - Applications YARN tuees" -ForegroundColor Green
Write-Host " - HDFS logs et checkpoints vides" -ForegroundColor Green
Write-Host " - HBase tables finales recreees puis HBase fermee" -ForegroundColor Green
Write-Host " - Cassandra $CASSANDRA_TABLE videe" -ForegroundColor Green
Write-Host " - Kafka topic $KAFKA_TOPIC recree puis Kafka/Zookeeper fermes" -ForegroundColor Green
Write-Host " - Hadoop ferme avec stop-hadoop.sh" -ForegroundColor Green
Write-Host " - Logs locaux nettoyes" -ForegroundColor Green
Write-Host ""
