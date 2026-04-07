import json
import time
import pandas as pd
from kafka import KafkaProducer

CSV_FILE = "cybersecurity_threat_detection_logs.csv"   # mets ici le bon nom du fichier
KAFKA_BROKER = "localhost:9092"
TOPIC = "cybersecurity-logs"

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    key_serializer=lambda k: k.encode("utf-8"),
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

df = pd.read_csv(CSV_FILE)

# Pour tester au début, on prend seulement 20 lignes
df = df.head(500)

for _, row in df.iterrows():
    message = {
        "timestamp": str(row["timestamp"]),
        "source_ip": str(row["source_ip"]),
        "dest_ip": str(row["dest_ip"]),
        "protocol": str(row["protocol"]),
        "action": str(row["action"]),
        "threat_label": str(row["threat_label"]),
        "log_type": str(row["log_type"]),
        "bytes_transferred": int(row["bytes_transferred"]),
        "user_agent": str(row["user_agent"]),
        "request_path": str(row["request_path"])
    }

    key = message["source_ip"]   # très important
    producer.send(TOPIC, key=key, value=message)
    print(f"sent -> key={key}, value={message}")

    time.sleep(0.4)  # simulation de streaming

producer.flush()
producer.close()
print("Envoi terminé.")