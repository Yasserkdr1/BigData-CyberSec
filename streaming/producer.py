import csv
import json
import time
from kafka import KafkaProducer

# Configuration Kafka
KAFKA_BROKER = "localhost:9092" # ou "hadoop-master:9092" si lancé depuis un conteneur
KAFKA_TOPIC = "cybersecurity-logs"
CSV_FILE_PATH = "attacks.csv"

def json_serializer(data):
    return json.dumps(data).encode("utf-8")

# Initialisation du producer Kafka
producer = KafkaProducer(
    bootstrap_servers=[KAFKA_BROKER],
    value_serializer=json_serializer
)

print(f"🚀 Début de la lecture du fichier {CSV_FILE_PATH}...")
print(f"📡 Envoi des données vers le topic Kafka '{KAFKA_TOPIC}'...")

try:
    with open(CSV_FILE_PATH, mode='r', encoding='utf-8') as file:
        # csv.DictReader convertit automatiquement chaque ligne en dictionnaire basé sur l'en-tête
        csv_reader = csv.DictReader(file)
        
        for row in csv_reader:
            # On s'assure que bytes_transferred est un entier (si la colonne existe)
            if 'bytes_transferred' in row and row['bytes_transferred'].isdigit():
                row['bytes_transferred'] = int(row['bytes_transferred'])
                
            # Envoi du dictionnaire en JSON vers Kafka
            producer.send(KAFKA_TOPIC, row)
            print(f"Envoyé : {row['source_ip']} -> {row['request_path']} ({row.get('action', '')})")
            
            # Petite pause pour simuler un flux en temps réel (streaming)
            time.sleep(1)

except FileNotFoundError:
    print(f"❌ Erreur : Le fichier {CSV_FILE_PATH} est introuvable à la racine du projet.")
except Exception as e:
    print(f"❌ Erreur inattendue : {e}")
finally:
    producer.flush()
    producer.close()
    print("✅ Fin de l'envoi des logs.")