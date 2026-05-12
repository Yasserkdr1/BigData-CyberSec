# Quick Documentation — CyberSec Big Data Project

This folder contains the essential steps to prepare, initialize, start, and stop the environment for the **Real-Time Cybersecurity Threat Detection** project.

## Recommended Order

1. Read `01_PREREQUIS_INSTALLATION.md`
2. Start the containers with Docker Compose
3. Perform one-time initialization with `02_INITIALISATION_ENVIRONNEMENT.md`
4. Start the pipeline with `03_DEMARRAGE_PIPELINE.md`
5. Stop or reset with `04_ARRET_RESET.md`

## Key Project Files

| File | Role |
|---|---|
| `docker-compose.yaml` | Docker container declarations |
| `start_all.ps1` / `start.sh` | Starts services and launches jobs (Windows / Linux) |
| `stop_reset_close_all.ps1` / `stop_reset.sh` | Stops jobs, resets data, and shuts down services (Windows / Linux) |
| `archive_to_hdfs.py` | Archives Kafka logs to HDFS |
| `streaming.py` | Real-time detection with Spark Streaming |
| `batch_f.py` | Spark batch processing and HBase writes |
| `app.py` | API/dashboard for consulting alerts |
