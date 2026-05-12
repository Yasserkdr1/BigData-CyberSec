# Détection de Menaces de Cybersécurité en Temps Réel

Ce projet met en œuvre une plateforme Big Data de détection de menaces de cybersécurité basée sur une architecture **Lambda**. Il combine un traitement historique des logs réseau, une détection temps réel, un stockage distribué et un dashboard de visualisation.

L’objectif est d’analyser des événements réseau afin d’identifier des comportements suspects ou malveillants tels que les scans, injections SQL, attaques XSS, accès sensibles, brute-force et transferts anormaux.

---

## Vue d’ensemble

Le système s’appuie sur plusieurs composants distribués :

- **Hadoop / HDFS** pour le stockage des logs archivés ;
- **Apache Spark** pour les traitements batch et streaming ;
- **Apache Kafka** pour l’ingestion continue des logs ;
- **Apache HBase** pour les vues analytiques historiques ;
- **Apache Cassandra** pour les alertes temps réel ;
- **Flask / JavaScript** pour le dashboard de supervision.

Le pipeline suit le principe suivant :

```text
Dataset CSV
   ↓
Kafka Producer
   ↓
Kafka Topic cybersecurity-logs
   ↓
Spark Streaming → Cassandra → Dashboard live
   ↓
Archivage HDFS
   ↓
Spark Batch → HBase → Dashboard historique
```

---

## Structure du projet

```text
.
├── batch/                         # Jobs Spark batch et traitements historiques
├── dashboard/                     # Application Flask et interface web
├── docs/                          # Documentation détaillée du projet
├── starting/                      # Scripts PowerShell de démarrage / arrêt / reset
├── streaming/                     # Producteur Kafka et jobs Spark Streaming
├── docker-compose.yaml            # Définition du cluster Docker
├── cybersecurity_threat_detection_logs.csv
├── mini_Db_Logs.csv
└── README.md
```

---

## Fonctionnalités principales

- ingestion continue de logs réseau via Kafka ;
- archivage des logs dans HDFS ;
- analyse batch des menaces historiques ;
- détection temps réel avec Spark Structured Streaming ;
- stockage des alertes live dans Cassandra ;
- stockage des vues batch dans HBase ;
- dashboard web avec indicateurs globaux, alertes live, IP à risque, machines ciblées et fiches d’investigation par IP.

---

## Démarrage rapide

Les étapes détaillées sont disponibles dans le dossier [`docs/`](./docs).

Résumé d’exécution :

```powershell
cd starting
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\start_all.ps1
```

Pour arrêter et réinitialiser l’environnement :

```powershell
cd starting
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\stop_reset_close_all.ps1
```

---

## Documentation

La documentation complète du projet est organisée dans le dossier [`docs/`](./docs) :

- prérequis et installation ;
- initialisation de l’environnement ;
- création des topics, keyspaces et tables ;
- démarrage du cluster et des jobs ;
- arrêt, nettoyage et reset ;
- commandes de vérification utiles.

---

## Dashboard

Le dashboard permet de suivre :

- les alertes live issues de Cassandra ;
- les statistiques batch issues de HBase ;
- les IP sources à risque ;
- les machines destinations ciblées ;
- les patterns d’attaque détectés ;
- les détails d’investigation pour une IP donnée.

---

## Technologies utilisées

| Composant | Rôle |
|---|---|
| Docker / Docker Compose | Orchestration locale du cluster |
| Hadoop / HDFS | Stockage distribué des logs |
| Kafka / Zookeeper | Ingestion temps réel |
| Spark | Traitement batch et streaming |
| HBase | Stockage des vues historiques |
| Cassandra | Stockage des alertes live |
| Flask | API backend du dashboard |
| HTML / CSS / JavaScript | Interface de visualisation |

---

## Auteur
