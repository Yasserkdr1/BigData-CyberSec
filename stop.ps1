Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "1) Affichage des applications YARN" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

docker exec -it hadoop-master bash -c "yarn application -list"

Write-Host ""
Write-Host "Tuez le streaming YARN avec :" -ForegroundColor Yellow
Write-Host "docker exec -it hadoop-master bash -c 'yarn application -kill <application_id>'"
Write-Host ""

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "2) Stop archive_to_hdfs sur worker3" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

docker exec hadoop-worker3 bash -c "pkill -f archive_to_hdfs.py || true"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "3) Stop batch_recent sur worker4" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

docker exec hadoop-worker4 bash -c "pkill -f batch_recent.py || true"
docker exec hadoop-worker4 bash -c "pkill -f 'while true; do spark-submit --master local\\[\\*\\] /root/batch_recent.py' || true"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "4) Stop batch_global sur worker5" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

docker exec hadoop-worker5 bash -c "pkill -f batch_global.py || true"
docker exec hadoop-worker5 bash -c "pkill -f 'while true; do spark-submit --master local\\[\\*\\] /root/batch_global.py' || true"

Write-Host "==================================================" -ForegroundColor Green
Write-Host "Arret des jobs locaux termine" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green