Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "1) Lancement archive_to_hdfs sur worker3" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

docker exec -d hadoop-worker3 bash -c "nohup spark-submit --master local[*] --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0 /root/archive_to_hdfs.py > /root/archive_to_hdfs.log 2>&1"

Start-Sleep -Seconds 8

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "2) Lancement batch_recent en boucle toutes les 2 min sur worker4" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

docker exec -d hadoop-worker4 bash -c "nohup bash -c 'while true; do spark-submit --master local[*] /root/batch_recent.py >> /root/batch_recent.log 2>&1; sleep 120; done' > /root/batch_recent_loop.log 2>&1"

Start-Sleep -Seconds 8

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "3) Lancement batch_global en boucle toutes les 5 min sur worker5" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

docker exec -d hadoop-worker5 bash -c "nohup bash -c 'while true; do spark-submit --master local[*] /root/batch_global.py >> /root/batch_global.log 2>&1; sleep 300; done' > /root/batch_global_loop.log 2>&1"

Start-Sleep -Seconds 10

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "4) Lancement streaming sur master en dernier (YARN)" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

docker exec -d hadoop-master bash -c "nohup spark-submit --master yarn --deploy-mode client --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0 /root/streaming.py > /root/streaming.log 2>&1"

Write-Host "==================================================" -ForegroundColor Green
Write-Host "Tous les jobs ont ete lances" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green

Write-Host ""
Write-Host "Verifier les logs avec :" -ForegroundColor Yellow
Write-Host "docker exec -it hadoop-worker3 bash -c 'tail -f /root/archive_to_hdfs.log'"
Write-Host "docker exec -it hadoop-worker4 bash -c 'tail -f /root/batch_recent.log'"
Write-Host "docker exec -it hadoop-worker5 bash -c 'tail -f /root/batch_global.log'"
Write-Host "docker exec -it hadoop-master  bash -c 'tail -f /root/streaming.log'"
Write-Host ""
Write-Host "Verifier YARN avec :" -ForegroundColor Yellow
Write-Host "docker exec -it hadoop-master bash -c 'yarn application -list'"