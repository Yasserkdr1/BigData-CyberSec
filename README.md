# 🛡️ Real-Time Cybersecurity Threat Detection

**Mini-Project Big Data - SITCN2**

Yo This is just our school mini-project for the Big Data

## 📖 Overview
This project implements a complete Big Data pipeline for detecting cybersecurity threats using a **Lambda Architecture**. The system analyzes network logs to detect historical attack patterns (Batch Processing) and identify active threats in real-time (Stream Processing).

## 🏗️ Architecture
The project is divided into three main layers:

* **Speed Layer (Real-Time):** Uses **Apache Kafka** and **Spark Streaming** to simulate and analyze continuous network traffic. It detects immediate threats like brute-force attacks and volumetric anomalies (DDoS/Exfiltration), storing the active alerts in **Cassandra**.
* **Batch Layer (Historical):** Uses **Hadoop (HDFS)** and **Spark Batch** to process massive amounts of historical log data. It calculates long-term IP reputation scores, identifies frequent SQLi/XSS attack paths, and stores the aggregated views in **HBase**.
* **Query Layer / Dashboard:** A unified view combining data from both HBase and Cassandra to present a complete timeline of historical trends and immediate threats.

## 🚀 Technologies Used
* **Data Processing:** Apache Spark (PySpark)
* **Message Broker:** Apache Kafka
* **Storage:** HDFS, Apache HBase, Apache Cassandra
* **Environment:** Docker & Docker Compose
* **Language:** Python 3.10

## ⚙️ How to Run

1. Clone the repository.
2. Ensure Docker and Docker Compose are installed on your machine.
3. To start the cluster and run the **Batch Layer** pipeline automatically, execute:
   \`\`\`bash
   ./run_batch.sh
   \`\`\`
4. Kmloo hadchi hhhh.