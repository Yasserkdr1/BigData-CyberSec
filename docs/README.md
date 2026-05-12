# Documentation rapide — Projet CyberSec Big Data

Ce dossier contient les étapes essentielles pour préparer, initialiser, démarrer et arrêter l'environnement du projet **Détection de menaces de cybersécurité en temps réel**.

## Ordre recommandé

1. Lire `01_PREREQUIS_INSTALLATION.md`
2. Lancer les conteneurs avec Docker Compose
3. Faire l'initialisation une seule fois avec `02_INITIALISATION_ENVIRONNEMENT.md`
4. Démarrer le pipeline avec `03_DEMARRAGE_PIPELINE.md`
5. Arrêter ou réinitialiser avec `04_ARRET_RESET.md`

## Fichiers principaux du projet

| Fichier | Rôle |
|---|---|
| `docker-compose.yaml` | Déclaration des conteneurs Docker |
| `start_all.ps1` | Démarre les services et lance les jobs |
| `stop_reset_close_all.ps1` | Stoppe les jobs, reset les données et ferme les services |
| `archive_to_hdfs.py` | Archive les logs Kafka vers HDFS |
| `streaming.py` | Détection temps réel Spark Streaming |
| `batch_f.py` ou `batch_spark.py` | Traitement batch Spark et écriture HBase |
| `app.py` | API/dashboard pour consulter les alertes |
