# ============================================================
# Script PowerShell - Demarrage services Big Data + lancement jobs
# Projet : Detection Menaces Cybersecurite Temps Reel
# IMPORTANT : ce script ne cree ni tables, ni schemas, ni topics.
# Il demarre seulement les services existants et lance les jobs.
# ============================================================

$ErrorActionPreference = "Stop"

# ---------------- CONFIGURATION ----------------
$MASTER_CONTAINER  = "hadoop-master"
$KAFKA_CONTAINER   = "hadoop-master"
$HBASE_CONTAINER   = "hadoop-master"
$ARCHIVE_CONTAINER = "hadoop-worker3"
$BATCH_CONTAINER   = "hadoop-worker5"
$STREAM_CONTAINER  = "hadoop-master"

$TOPIC_NAME = "cybersecurity-logs"
$SPARK_KAFKA_PACKAGE = "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0"

# Attente initiale apres start-hbase.sh, car HBase prend souvent du temps
$HBASE_INITIAL_WAIT_SECONDS = 60

# Verification HBase en boucle apres l'attente initiale
$HBASE_MAX_WAIT_SECONDS = 180
$HBASE_CHECK_INTERVAL_SECONDS = 10

# ---------------- FONCTIONS ----------------
function Write-Step($message) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $message -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Write-Ok($message) {
    Write-Host "[OK] $message" -ForegroundColor Green
}

function Write-Warn($message) {
    Write-Host "[WARN] $message" -ForegroundColor Yellow
}

function Write-Fail($message) {
    Write-Host "[ERREUR] $message" -ForegroundColor Red
}

function Test-ContainerRunning($containerName) {
    $status = docker inspect -f '{{.State.Running}}' $containerName 2>$null
    return ($status -eq "true")
}

function Require-Container($containerName) {
    if (-not (Test-ContainerRunning $containerName)) {
        Write-Fail "Le conteneur '$containerName' n'est pas demarre. Demarre tes conteneurs Docker avant d'executer ce script."
        exit 1
    }
    Write-Ok "Conteneur actif : $containerName"
}

function Start-ServiceCommand($containerName, $serviceCommand, $serviceName) {
    Write-Step "Demarrage $serviceName"

    # Chemin absolu (/root/start-hadoop.sh) => test fichier.
    # Commande simple (start-hbase.sh) => test dans le PATH du conteneur.
    $cmd = @"
if echo '$serviceCommand' | grep -q '^/'; then
    if [ -f '$serviceCommand' ]; then
        bash '$serviceCommand'
    else
        echo 'Script introuvable: $serviceCommand'
        exit 2
    fi
else
    if command -v '$serviceCommand' >/dev/null 2>&1; then
        '$serviceCommand'
    else
        echo 'Commande introuvable dans le PATH: $serviceCommand'
        exit 2
    fi
fi
"@

    docker exec $containerName bash -lc $cmd
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "$serviceName lance"
    } else {
        Write-Warn "$serviceName : commande/script non trouve ou erreur. Verifie : $serviceCommand dans $containerName."
    }
}

function Wait-Countdown($seconds, $label) {
    Write-Step $label
    for ($i = $seconds; $i -gt 0; $i--) {
        $percent = (($seconds - $i) / $seconds) * 100
        Write-Progress -Activity $label -Status "Attente restante : $i seconde(s)" -PercentComplete $percent
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity $label -Completed
    Write-Ok "Attente terminee"
}

function Wait-HBaseReady() {
    Write-Step "Verification HBase avant Thrift/jobs"

    $elapsed = 0
    while ($elapsed -le $HBASE_MAX_WAIT_SECONDS) {
        $checkCmd = "echo 'status' | hbase shell -n 2>/dev/null | grep -E 'active master|servers|requests' >/dev/null"
        docker exec $HBASE_CONTAINER bash -lc $checkCmd 2>$null

        if ($LASTEXITCODE -eq 0) {
            Write-Ok "HBase semble pret"
            return
        }

        Write-Host "HBase pas encore pret... nouvelle verification dans $HBASE_CHECK_INTERVAL_SECONDS sec ($elapsed/$HBASE_MAX_WAIT_SECONDS sec)" -ForegroundColor Yellow
        Start-Sleep -Seconds $HBASE_CHECK_INTERVAL_SECONDS
        $elapsed += $HBASE_CHECK_INTERVAL_SECONDS
    }

    Write-Warn "HBase n'a pas repondu clairement apres $HBASE_MAX_WAIT_SECONDS sec. Le script continue quand meme, mais Thrift/jobs peuvent echouer si HBase n'est pas pret."
}

function Test-FileInContainer($containerName, $filePath) {
    docker exec $containerName bash -lc "test -f '$filePath'" 2>$null
    return ($LASTEXITCODE -eq 0)
}

# ---------------- DEBUT ----------------
Write-Step "Verification des conteneurs deja demarres"
$containers = @($MASTER_CONTAINER, $KAFKA_CONTAINER, $HBASE_CONTAINER, $ARCHIVE_CONTAINER, $BATCH_CONTAINER, $STREAM_CONTAINER) | Select-Object -Unique
foreach ($c in $containers) {
    Require-Container $c
}

# Duree batch interactive
Write-Step "Configuration interactive du batch"
$batchInterval = Read-Host "Entrez la duree entre deux executions batch, en secondes. Exemple 100 ou 900"
if (-not ($batchInterval -match '^[0-9]+$') -or [int]$batchInterval -le 0) {
    Write-Fail "Duree invalide. Entre un nombre entier positif, par exemple 100."
    exit 1
}
Write-Ok "Intervalle batch choisi : $batchInterval secondes"

# ---------------- SERVICES ----------------
Start-ServiceCommand $MASTER_CONTAINER "/root/start-hadoop.sh" "Hadoop / HDFS / YARN"

Write-Step "Verification HDFS"
docker exec $MASTER_CONTAINER bash -lc "hdfs dfsadmin -report >/dev/null 2>&1"
if ($LASTEXITCODE -eq 0) {
    Write-Ok "HDFS repond"
} else {
    Write-Warn "HDFS ne repond pas encore clairement"
}

Write-Step "Verification YARN"
docker exec $MASTER_CONTAINER bash -lc "yarn node -list >/dev/null 2>&1"
if ($LASTEXITCODE -eq 0) {
    Write-Ok "YARN repond"
} else {
    Write-Warn "YARN ne repond pas encore clairement"
}

Start-ServiceCommand $KAFKA_CONTAINER "/root/start-kafka-zookeeper.sh" "Kafka / Zookeeper"

Write-Step "Verification topic Kafka existant"
$kafkaCheckCmd = "kafka-topics.sh --bootstrap-server hadoop-master:9092 --list 2>/dev/null | grep -w '$TOPIC_NAME' >/dev/null"
docker exec $KAFKA_CONTAINER bash -lc $kafkaCheckCmd
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Topic Kafka trouve : $TOPIC_NAME"
} else {
    Write-Warn "Topic Kafka '$TOPIC_NAME' non trouve ou Kafka pas encore pret. Le script ne le cree pas."
}

# HBase : start-hbase.sh est une commande du PATH, pas un fichier /root/start-hbase.sh
Start-ServiceCommand $HBASE_CONTAINER "start-hbase.sh" "HBase"

# Timer explicite pour HBase
Wait-Countdown $HBASE_INITIAL_WAIT_SECONDS "Attente initiale pour laisser HBase demarrer"
Wait-HBaseReady

# Thrift apres HBase pret
Write-Step "Demarrage HBase Thrift Server"
docker exec -d $HBASE_CONTAINER bash -lc "nohup hbase thrift start > /root/hbase-thrift.log 2>&1"
if ($LASTEXITCODE -eq 0) {
    Write-Ok "HBase Thrift Server lance en arriere-plan"
} else {
    Write-Warn "Impossible de lancer HBase Thrift Server"
}

# Petite attente Thrift
Wait-Countdown 10 "Attente courte apres demarrage Thrift"

# ---------------- VERIFICATION FICHIERS JOBS ----------------
Write-Step "Verification des fichiers jobs"
$checks = @(
    @{Container=$ARCHIVE_CONTAINER; File="/root/archive_to_hdfs.py"},
    @{Container=$BATCH_CONTAINER;   File="/root/batch_f.py"},
    @{Container=$STREAM_CONTAINER;  File="/root/streaming.py"}
)

foreach ($item in $checks) {
    if (Test-FileInContainer $item.Container $item.File) {
        Write-Ok "$($item.File) existe dans $($item.Container)"
    } else {
        Write-Fail "$($item.File) introuvable dans $($item.Container). Corrige avant de lancer les jobs."
        exit 1
    }
}

# ---------------- LANCEMENT JOBS ----------------
Write-Step "Lancement archive_to_hdfs.py"
$archiveCmd = "nohup spark-submit --master local[*] --packages $SPARK_KAFKA_PACKAGE /root/archive_to_hdfs.py > /root/archive_to_hdfs.log 2>&1"
docker exec -d $ARCHIVE_CONTAINER bash -lc $archiveCmd
Write-Ok "Job archive_to_hdfs.py lance"

Write-Step "Lancement streaming.py separement du batch"
$streamCmd = "nohup spark-submit --master yarn --deploy-mode client --packages $SPARK_KAFKA_PACKAGE /root/streaming.py > /root/streaming.log 2>&1"
docker exec -d $STREAM_CONTAINER bash -lc $streamCmd
Write-Ok "Job streaming.py lance"

Write-Step "Lancement batch_f.py en boucle : sleep $batchInterval sec, puis execution"

# On ecrit le script bash dans un fichier temporaire Windows pour eviter les problemes de guillemets PowerShell/Bash.
$tmpSh = Join-Path $env:TEMP "batch_loop.sh"
$lines = @(
    '#!/bin/bash',
    'while true; do',
    '    echo "==== Waiting INTERVAL_PLACEHOLDER sec before batch : $(date) ====" >> /root/batch_global_final.log',
    '    sleep INTERVAL_PLACEHOLDER',
    '    echo "==== Batch start : $(date) ====" >> /root/batch_global_final.log',
    '    spark-submit --master local[*] /root/batch_f.py >> /root/batch_global_final.log 2>&1',
    '    echo "==== Batch end : $(date) ====" >> /root/batch_global_final.log',
    'done'
)
$scriptContent = ($lines -join "`n").Replace("INTERVAL_PLACEHOLDER", $batchInterval)
[System.IO.File]::WriteAllText($tmpSh, $scriptContent)

$remoteBatchScript = "$($BATCH_CONTAINER):/root/batch_loop.sh"
& docker cp $tmpSh $remoteBatchScript
if ($LASTEXITCODE -ne 0) {
    Write-Fail "docker cp echoue : impossible de copier batch_loop.sh dans $BATCH_CONTAINER"
    exit 1
}

& docker exec $BATCH_CONTAINER bash -c "chmod +x /root/batch_loop.sh"
if ($LASTEXITCODE -ne 0) {
    Write-Fail "chmod echoue dans $BATCH_CONTAINER"
    exit 1
}

& docker exec -d $BATCH_CONTAINER bash -c "nohup /root/batch_loop.sh > /root/batch_global_final_loop.log 2>&1"
if ($LASTEXITCODE -eq 0) {
    Write-Ok "Batch lance dans $BATCH_CONTAINER : sleep $batchInterval sec, puis execution, puis sleep/execution..."
} else {
    Write-Fail "Impossible de lancer le batch dans $BATCH_CONTAINER"
    exit 1
}

# ---------------- FIN ----------------
Write-Step "Demarrage termine"
Write-Host "Logs utiles :" -ForegroundColor Cyan
Write-Host "docker exec -it $STREAM_CONTAINER tail -f /root/streaming.log"
Write-Host "docker exec -it $BATCH_CONTAINER tail -f /root/batch_global_final.log"
Write-Host "docker exec -it $BATCH_CONTAINER tail -f /root/batch_global_final_loop.log"
Write-Host "docker exec -it $ARCHIVE_CONTAINER tail -f /root/archive_to_hdfs.log"
Write-Host "docker exec -it $HBASE_CONTAINER tail -f /root/hbase-thrift.log"

Write-Host ""
Write-Host "Pour arreter les jobs :" -ForegroundColor Cyan
Write-Host "docker exec -it $STREAM_CONTAINER pkill -f streaming.py"
Write-Host "docker exec -it $BATCH_CONTAINER pkill -f batch_f.py"
Write-Host "docker exec -it $ARCHIVE_CONTAINER pkill -f archive_to_hdfs.py"
