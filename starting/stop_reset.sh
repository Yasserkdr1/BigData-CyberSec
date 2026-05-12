#!/usr/bin/env bash
# ============================================================
# stop_reset.sh — Linux/macOS/WSL stop + full reset script
# Port of stop_reset_close_all.ps1 to Bash
#
# Stops jobs, cleans data, resets views, and shuts down services.
#
# Usage:
#   chmod +x stop_reset.sh
#   ./stop_reset.sh
# ============================================================

set -eo pipefail

# ======================== COLORS ============================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

# ======================= CONFIG =============================
MASTER_CONTAINER="hadoop-master"
ARCHIVE_CONTAINER="hadoop-worker3"
BATCH_CONTAINER="hadoop-worker5"
STREAM_CONTAINER="hadoop-master"
CASSANDRA_CONTAINER="cassandra"

KAFKA_TOPIC="cybersecurity-logs"
KAFKA_PARTITIONS=3
KAFKA_REPLICATION=1
CASSANDRA_KEYSPACE="cybersec"
CASSANDRA_TABLE="realtime_alerts_live"

# ====================== FUNCTIONS ===========================

step() {
    echo ""
    echo -e "${CYAN}============================================================"
    echo -e "$1"
    echo -e "============================================================${NC}"
}

ok() {
    echo -e "${GREEN}[OK]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

fail() {
    echo -e "${RED}[ERROR]${NC} $1"
}

docker_exec() {
    local container="$1"
    shift
    local cmd="$*"
    echo ""
    echo -e "${YELLOW}>> docker exec $container bash -lc \"$cmd\"${NC}"
    docker exec "$container" bash -lc "$cmd" || true
}

container_running() {
    local name="$1"
    docker ps --format "{{.Names}}" | grep -q "^${name}$"
}

container_exists() {
    local name="$1"
    docker ps -a --format "{{.Names}}" | grep -q "^${name}$"
}

check_container() {
    local name="$1"
    if ! container_exists "$name"; then
        fail "Container not found: $name"
        exit 1
    fi
    if ! container_running "$name"; then
        fail "Container not running: $name"
        echo -e "${RED}Start your Docker containers before running this script.${NC}"
        exit 1
    fi
}

# ===================== START SCRIPT =========================

echo -e "${BOLD}${RED}"
echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║   BigData-CyberSec — STOP + FULL RESET + SHUTDOWN     ║"
echo "  ║   HDFS + HBase + Cassandra + Kafka                    ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================================
# 0. Verify containers
# ============================================================
step "0. Verifying containers"
check_container "$MASTER_CONTAINER"
check_container "$ARCHIVE_CONTAINER"
check_container "$BATCH_CONTAINER"
check_container "$STREAM_CONTAINER"
check_container "$CASSANDRA_CONTAINER"
ok "All required containers are running."

# ============================================================
# 1. Stop Spark / Python jobs
# ============================================================
step "1. Stopping Spark / Python jobs"

docker_exec "$ARCHIVE_CONTAINER" "pkill -f archive_to_hdfs.py || true; pkill -f 'spark-submit.*archive_to_hdfs.py' || true"
docker_exec "$BATCH_CONTAINER" "pkill -f batch_loop.sh || true; pkill -f 'while true' || true; pkill -f '/root/batch_f.py' || true; pkill -f '/root/batch_global_final.py' || true; pkill -f 'spark-submit.*batch_f.py' || true; pkill -f 'spark-submit.*batch_global_final.py' || true"
docker_exec "$STREAM_CONTAINER" "pkill -f '/root/streaming.py' || true; pkill -f 'spark-submit.*streaming.py' || true"

echo ""
echo -e "${MAGENTA}Waiting 5 seconds after killing jobs...${NC}"
sleep 5

# ============================================================
# 2. Kill remaining YARN apps
# ============================================================
step "2. Killing remaining YARN applications"
docker_exec "$MASTER_CONTAINER" "yarn application -list 2>/dev/null | awk '/application_/ {print \$1}' | xargs -r -n1 yarn application -kill || true"

step "3. Verifying remaining job processes"
docker_exec "$STREAM_CONTAINER" "ps -ef | grep -E 'streaming.py|spark-submit' | grep -v grep || true"
docker_exec "$BATCH_CONTAINER" "ps -ef | grep -E 'batch_loop.sh|batch_f.py|batch_global_final.py|spark-submit|while true' | grep -v grep || true"
docker_exec "$MASTER_CONTAINER" "yarn application -list || true"

# ============================================================
# 4. Reset HDFS
# ============================================================
step "4. Cleaning HDFS"

docker_exec "$MASTER_CONTAINER" "hdfs dfsadmin -safemode leave || true"
docker_exec "$MASTER_CONTAINER" "hdfs dfs -rm -r -f /data/cybersecurity/logs || true"
docker_exec "$MASTER_CONTAINER" "hdfs dfs -rm -r -f /tmp/checkpoints || true"
docker_exec "$MASTER_CONTAINER" "hdfs dfs -rm -r -f /tmp/spark-checkpoints || true"
docker_exec "$MASTER_CONTAINER" "hdfs dfs -mkdir -p /data/cybersecurity/logs"
docker_exec "$MASTER_CONTAINER" "hdfs dfs -mkdir -p /tmp/checkpoints"
docker_exec "$MASTER_CONTAINER" "hdfs dfs -mkdir -p /tmp/spark-checkpoints"
docker_exec "$MASTER_CONTAINER" "hdfs dfs -ls /data/cybersecurity || true"
docker_exec "$MASTER_CONTAINER" "hdfs dfs -ls /tmp || true"

# ============================================================
# 5. Reset HBase tables
# ============================================================
step "5. Resetting HBase: dropping and recreating tables"

# Create the HBase reset script
docker exec "$MASTER_CONTAINER" bash -c 'cat > /tmp/hbase_reset_final.hb << '\''HBASE_EOF'\''
def reset_table(t)
  if exists(t)
    disable t if is_enabled(t)
    drop t
  end
  create t, '\''cf'\''
end

if exists('\''recent_ip_stats'\'')
  disable '\''recent_ip_stats'\'' if is_enabled('\''recent_ip_stats'\'')
  drop '\''recent_ip_stats'\''
end

if exists('\''recent_protocol_stats'\'')
  disable '\''recent_protocol_stats'\'' if is_enabled('\''recent_protocol_stats'\'')
  drop '\''recent_protocol_stats'\''
end

if exists('\''recent_attack_patterns'\'')
  disable '\''recent_attack_patterns'\'' if is_enabled('\''recent_attack_patterns'\'')
  drop '\''recent_attack_patterns'\''
end

reset_table '\''global_ip_stats'\''
reset_table '\''global_protocol_stats'\''
reset_table '\''global_attack_patterns'\''
reset_table '\''ip_reputation'\''
reset_table '\''target_ip_stats'\''
reset_table '\''threat_timeline'\''
reset_table '\''attacker_victim_stats'\''
reset_table '\''high_risk_ips'\''
reset_table '\''ip_attack_types'\''
reset_table '\''ip_historical_alerts'\''

list
HBASE_EOF'

docker_exec "$MASTER_CONTAINER" "hbase shell -n /tmp/hbase_reset_final.hb"
docker_exec "$MASTER_CONTAINER" "echo 'list' | hbase shell -n"

# ============================================================
# 6. Truncate Cassandra
# ============================================================
step "6. Truncating Cassandra"
echo ""
echo -e "${YELLOW}>> docker exec $CASSANDRA_CONTAINER cqlsh -e \"USE $CASSANDRA_KEYSPACE; TRUNCATE $CASSANDRA_TABLE;\"${NC}"
docker exec "$CASSANDRA_CONTAINER" cqlsh -e "USE $CASSANDRA_KEYSPACE; TRUNCATE $CASSANDRA_TABLE;"

# ============================================================
# 7. Reset Kafka topic
# ============================================================
step "7. Resetting Kafka topic: $KAFKA_TOPIC"

docker_exec "$MASTER_CONTAINER" "kafka-topics.sh --bootstrap-server localhost:9092 --delete --topic $KAFKA_TOPIC || true"

echo ""
echo -e "${MAGENTA}Waiting 5 seconds after topic deletion...${NC}"
sleep 5

docker_exec "$MASTER_CONTAINER" "kafka-topics.sh --bootstrap-server localhost:9092 --create --topic $KAFKA_TOPIC --partitions $KAFKA_PARTITIONS --replication-factor $KAFKA_REPLICATION || true"

# ============================================================
# 8. Clean local logs
# ============================================================
step "8. Cleaning local job logs"

docker_exec "$ARCHIVE_CONTAINER" "rm -f /root/archive_to_hdfs.log || true"
docker_exec "$BATCH_CONTAINER" "rm -f /root/batch_global_final.log /root/batch_global_final_loop.log /root/batch_f.log /root/batch_loop.sh || true"
docker_exec "$STREAM_CONTAINER" "rm -f /root/streaming.log /root/hbase-thrift.log || true"

# ============================================================
# 9. Final verification before shutdown
# ============================================================
step "9. Final verification before shutting down services"

docker_exec "$MASTER_CONTAINER" "hdfs dfs -ls -R /data/cybersecurity/logs || true"
docker_exec "$MASTER_CONTAINER" "echo \"scan 'ip_reputation', {LIMIT => 5}\" | hbase shell -n || true"
docker_exec "$MASTER_CONTAINER" "echo \"scan 'ip_historical_alerts', {LIMIT => 5}\" | hbase shell -n || true"

echo ""
echo -e "${YELLOW}>> docker exec $CASSANDRA_CONTAINER cqlsh -e \"USE $CASSANDRA_KEYSPACE; SELECT COUNT(*) FROM $CASSANDRA_TABLE;\"${NC}"
docker exec "$CASSANDRA_CONTAINER" cqlsh -e "USE $CASSANDRA_KEYSPACE; SELECT COUNT(*) FROM $CASSANDRA_TABLE;"

docker_exec "$MASTER_CONTAINER" "kafka-topics.sh --bootstrap-server localhost:9092 --describe --topic $KAFKA_TOPIC || true"
docker_exec "$MASTER_CONTAINER" "yarn application -list || true"

# ============================================================
# 10. Shut down services
# ============================================================
step "10. Shutting down services"

step "10.1 Stop HBase Thrift Server"
docker_exec "$MASTER_CONTAINER" "pkill -f 'hbase.*thrift' || true; pkill -f 'ThriftServer' || true"

step "10.2 Stop HBase"
docker_exec "$MASTER_CONTAINER" "stop-hbase.sh || true"

step "10.3 Stop Kafka and Zookeeper"
docker_exec "$MASTER_CONTAINER" "pkill -f 'kafka.Kafka' || true; pkill -f 'Kafka' || true; pkill -f 'QuorumPeerMain' || true; pkill -f 'zookeeper' || true"

step "10.4 Stop Hadoop"
docker_exec "$MASTER_CONTAINER" "if [ -f /root/stop-hadoop.sh ]; then bash /root/stop-hadoop.sh; else stop-hadoop.sh || true; fi"

echo ""
echo -e "${MAGENTA}Waiting 5 seconds after service shutdown...${NC}"
sleep 5

step "11. Verifying remaining processes"
docker_exec "$MASTER_CONTAINER" "jps || true"
docker_exec "$MASTER_CONTAINER" "ps -ef | grep -E 'NameNode|DataNode|ResourceManager|NodeManager|HMaster|HRegionServer|Kafka|QuorumPeerMain|zookeeper|ThriftServer' | grep -v grep || true"

# ==================== SUMMARY ===============================
step "STOP + RESET + SHUTDOWN COMPLETE"

echo -e "${GREEN}Environment cleaned and services shut down:${NC}"
echo -e "  ${GREEN}- Spark/Python jobs stopped${NC}"
echo -e "  ${GREEN}- YARN applications killed${NC}"
echo -e "  ${GREEN}- HDFS logs and checkpoints cleared${NC}"
echo -e "  ${GREEN}- HBase tables recreated, then HBase shut down${NC}"
echo -e "  ${GREEN}- Cassandra $CASSANDRA_TABLE truncated${NC}"
echo -e "  ${GREEN}- Kafka topic $KAFKA_TOPIC recreated, then Kafka/Zookeeper shut down${NC}"
echo -e "  ${GREEN}- Hadoop shut down${NC}"
echo -e "  ${GREEN}- Local logs cleaned${NC}"
echo ""
echo -e "${BOLD}${CYAN}Environment is clean. Ready for next run.${NC}"
