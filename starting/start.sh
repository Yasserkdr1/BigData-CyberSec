#!/usr/bin/env bash
# ============================================================
# start.sh — Linux/macOS/WSL startup script for BigData-CyberSec
# Port of start_all.ps1 to Bash
#
# This script does NOT create tables, schemas, or topics.
# It only starts existing services and launches the Spark jobs.
#
# Usage:
#   chmod +x start.sh
#   ./start.sh
#   ./start.sh --batch-interval 100
# ============================================================

set -euo pipefail

# ======================== COLORS ============================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ======================= CONFIG =============================
MASTER_CONTAINER="hadoop-master"
KAFKA_CONTAINER="hadoop-master"
HBASE_CONTAINER="hadoop-master"
ARCHIVE_CONTAINER="hadoop-worker3"
BATCH_CONTAINER="hadoop-worker5"
STREAM_CONTAINER="hadoop-master"

TOPIC_NAME="cybersecurity-logs"
SPARK_KAFKA_PACKAGE="org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0"

# Wait times
HBASE_INITIAL_WAIT_SECONDS=60
HBASE_MAX_WAIT_SECONDS=180
HBASE_CHECK_INTERVAL_SECONDS=10

# Default batch interval (can be overridden via --batch-interval)
BATCH_INTERVAL=""

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

container_running() {
    local name="$1"
    local status
    status=$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo "false")
    [[ "$status" == "true" ]]
}

require_container() {
    local name="$1"
    if ! container_running "$name"; then
        fail "Container '$name' is not running. Start your Docker containers first."
        exit 1
    fi
    ok "Container active: $name"
}

start_service() {
    local container="$1"
    local cmd="$2"
    local service_name="$3"

    step "Starting $service_name"

    if docker exec "$container" bash -lc "$cmd" 2>/dev/null; then
        ok "$service_name launched"
    else
        warn "$service_name: command/script not found or error. Check: $cmd in $container."
    fi
}

countdown() {
    local seconds="$1"
    local label="$2"

    step "$label"
    for ((i=seconds; i>0; i--)); do
        printf "\r${MAGENTA}Waiting: %d second(s) remaining...${NC}" "$i"
        sleep 1
    done
    echo ""
    ok "Wait complete"
}

wait_hbase_ready() {
    step "Checking HBase before Thrift/jobs"

    local elapsed=0
    while [[ $elapsed -le $HBASE_MAX_WAIT_SECONDS ]]; do
        if docker exec "$HBASE_CONTAINER" bash -lc \
            "echo 'status' | hbase shell -n 2>/dev/null | grep -E 'active master|servers|requests' >/dev/null" 2>/dev/null; then
            ok "HBase is ready"
            return
        fi

        echo -e "${YELLOW}HBase not ready yet... retrying in ${HBASE_CHECK_INTERVAL_SECONDS}s (${elapsed}/${HBASE_MAX_WAIT_SECONDS}s)${NC}"
        sleep "$HBASE_CHECK_INTERVAL_SECONDS"
        elapsed=$((elapsed + HBASE_CHECK_INTERVAL_SECONDS))
    done

    warn "HBase didn't respond clearly after ${HBASE_MAX_WAIT_SECONDS}s. Continuing anyway, but Thrift/jobs may fail."
}

file_in_container() {
    local container="$1"
    local filepath="$2"
    docker exec "$container" bash -lc "test -f '$filepath'" 2>/dev/null
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --batch-interval SECONDS   Set the batch execution interval (default: prompt)"
    echo "  --help                     Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 --batch-interval 100"
}

# =================== PARSE ARGS =============================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --batch-interval)
            BATCH_INTERVAL="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            fail "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# ===================== START SCRIPT =========================

echo -e "${BOLD}${CYAN}"
echo "  ╔════════════════════════════════════════════════════════╗"
echo "  ║     BigData-CyberSec Pipeline Startup Script          ║"
echo "  ║     Real-Time Cybersecurity Threat Detection          ║"
echo "  ╚════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ------------------ Container checks ------------------------
step "Checking containers"
unique_containers=($(echo "$MASTER_CONTAINER $KAFKA_CONTAINER $HBASE_CONTAINER $ARCHIVE_CONTAINER $BATCH_CONTAINER $STREAM_CONTAINER" | tr ' ' '\n' | sort -u))
for c in "${unique_containers[@]}"; do
    require_container "$c"
done

# ------------------ Batch interval config -------------------
if [[ -z "$BATCH_INTERVAL" ]]; then
    step "Interactive batch interval configuration"
    read -rp "Enter the duration between batch executions (seconds). Example 100 or 900: " BATCH_INTERVAL
fi

if ! [[ "$BATCH_INTERVAL" =~ ^[0-9]+$ ]] || [[ "$BATCH_INTERVAL" -le 0 ]]; then
    fail "Invalid interval. Enter a positive integer, e.g. 100."
    exit 1
fi
ok "Batch interval: ${BATCH_INTERVAL}s"

# ------------------ Start services --------------------------

# 1. Hadoop / HDFS / YARN
start_service "$MASTER_CONTAINER" "/root/start-hadoop.sh" "Hadoop / HDFS / YARN"

step "Checking HDFS"
if docker exec "$MASTER_CONTAINER" bash -lc "hdfs dfsadmin -report >/dev/null 2>&1"; then
    ok "HDFS responding"
else
    warn "HDFS not responding yet"
fi

step "Checking YARN"
if docker exec "$MASTER_CONTAINER" bash -lc "yarn node -list >/dev/null 2>&1"; then
    ok "YARN responding"
else
    warn "YARN not responding yet"
fi

# 2. Kafka / Zookeeper
start_service "$KAFKA_CONTAINER" "/root/start-kafka-zookeeper.sh" "Kafka / Zookeeper"

step "Checking Kafka topic"
if docker exec "$KAFKA_CONTAINER" bash -lc \
    "kafka-topics.sh --bootstrap-server hadoop-master:9092 --list 2>/dev/null | grep -w '$TOPIC_NAME' >/dev/null" 2>/dev/null; then
    ok "Kafka topic found: $TOPIC_NAME"
else
    warn "Kafka topic '$TOPIC_NAME' not found or Kafka not ready. This script does not create it."
fi

# 3. HBase
start_service "$HBASE_CONTAINER" "start-hbase.sh" "HBase"

# Explicit timer for HBase startup
countdown "$HBASE_INITIAL_WAIT_SECONDS" "Initial wait for HBase to start"
wait_hbase_ready

# 4. HBase Thrift Server (after HBase is ready)
step "Starting HBase Thrift Server"
docker exec -d "$HBASE_CONTAINER" bash -lc "nohup hbase thrift start > /root/hbase-thrift.log 2>&1"
ok "HBase Thrift Server launched in background"

# Short wait after Thrift
countdown 10 "Short wait after Thrift startup"

# ------------------ Verify job files ------------------------
step "Verifying job files in containers"

declare -A job_files=(
    ["$ARCHIVE_CONTAINER"]="/root/archive_to_hdfs.py"
    ["$BATCH_CONTAINER"]="/root/batch_f.py"
    ["$STREAM_CONTAINER"]="/root/streaming.py"
)

for container in "${!job_files[@]}"; do
    filepath="${job_files[$container]}"
    if file_in_container "$container" "$filepath"; then
        ok "$filepath exists in $container"
    else
        fail "$filepath not found in $container. Fix before launching jobs."
        exit 1
    fi
done

# ------------------ Launch Spark jobs -----------------------

# 1. Archive to HDFS
step "Launching archive_to_hdfs.py"
docker exec -d "$ARCHIVE_CONTAINER" bash -lc \
    "nohup spark-submit --master local[*] --packages $SPARK_KAFKA_PACKAGE /root/archive_to_hdfs.py > /root/archive_to_hdfs.log 2>&1"
ok "Job archive_to_hdfs.py launched"

# 2. Streaming (speed layer)
step "Launching streaming.py"
docker exec -d "$STREAM_CONTAINER" bash -lc \
    "nohup spark-submit --master yarn --deploy-mode client --packages $SPARK_KAFKA_PACKAGE /root/streaming.py > /root/streaming.log 2>&1"
ok "Job streaming.py launched"

# 3. Batch (looping)
step "Launching batch_f.py in loop: sleep ${BATCH_INTERVAL}s, then execute"

# Create the batch loop script
docker exec "$BATCH_CONTAINER" bash -c "cat > /root/batch_loop.sh << 'BATCH_EOF'
#!/bin/bash
while true; do
    echo \"==== Waiting ${BATCH_INTERVAL} sec before batch : \$(date) ====\" >> /root/batch_global_final.log
    sleep ${BATCH_INTERVAL}
    echo \"==== Batch start : \$(date) ====\" >> /root/batch_global_final.log
    spark-submit --master local[*] /root/batch_f.py >> /root/batch_global_final.log 2>&1
    echo \"==== Batch end : \$(date) ====\" >> /root/batch_global_final.log
done
BATCH_EOF"

docker exec "$BATCH_CONTAINER" bash -c "chmod +x /root/batch_loop.sh"

docker exec -d "$BATCH_CONTAINER" bash -c "nohup /root/batch_loop.sh > /root/batch_global_final_loop.log 2>&1"
ok "Batch launched in $BATCH_CONTAINER: sleep ${BATCH_INTERVAL}s → execute → repeat"

# ------------------ Done ------------------------------------
step "Startup complete"

echo -e "${CYAN}Useful logs:${NC}"
echo -e "  ${YELLOW}docker exec -it $STREAM_CONTAINER tail -f /root/streaming.log${NC}"
echo -e "  ${YELLOW}docker exec -it $BATCH_CONTAINER tail -f /root/batch_global_final.log${NC}"
echo -e "  ${YELLOW}docker exec -it $BATCH_CONTAINER tail -f /root/batch_global_final_loop.log${NC}"
echo -e "  ${YELLOW}docker exec -it $ARCHIVE_CONTAINER tail -f /root/archive_to_hdfs.log${NC}"
echo -e "  ${YELLOW}docker exec -it $HBASE_CONTAINER tail -f /root/hbase-thrift.log${NC}"

echo ""
echo -e "${CYAN}To stop the jobs:${NC}"
echo -e "  ${YELLOW}docker exec -it $STREAM_CONTAINER pkill -f streaming.py${NC}"
echo -e "  ${YELLOW}docker exec -it $BATCH_CONTAINER pkill -f batch_f.py${NC}"
echo -e "  ${YELLOW}docker exec -it $ARCHIVE_CONTAINER pkill -f archive_to_hdfs.py${NC}"

echo ""
echo -e "${GREEN}${BOLD}Pipeline is live. Happy hunting. 🔐${NC}"
