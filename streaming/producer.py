import json
import time
import pandas as pd
from kafka import KafkaProducer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CSV_FILE = BASE_DIR.parent / "cybersecurity_threat_detection_logs.csv"

KAFKA_BROKER = "localhost:9092"
TOPIC = "cybersecurity-logs"

# --- Nombre de lignes initiales a envoyer ---
INITIAL_ROWS = 2000

# --- Taille par defaut des lots suivants ---
next = 500

# --- Delai entre chaque message (secondes) ---
DELAY_S = 0.2

producer = KafkaProducer(
    bootstrap_servers=KAFKA_BROKER,
    key_serializer=lambda k: k.encode("utf-8"),
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

df = pd.read_csv(CSV_FILE)
total_rows = len(df)

def send_rows(dataframe):
    print("Envoi en cours...", end="\r", flush=True)
    for _, row in dataframe.iterrows():
        message = {
            "timestamp":         str(row["timestamp"]),
            "source_ip":         str(row["source_ip"]),
            "dest_ip":           str(row["dest_ip"]),
            "protocol":          str(row["protocol"]),
            "action":            str(row["action"]),
            "threat_label":      str(row["threat_label"]),
            "log_type":          str(row["log_type"]),
            "bytes_transferred": int(row["bytes_transferred"]),
            "user_agent":        str(row["user_agent"]),
            "request_path":      str(row["request_path"])
        }
        producer.send(TOPIC, key=message["source_ip"], value=message)
        time.sleep(DELAY_S)
    producer.flush()
    print("Envoi termine.    ")

# --- Envoi initial ---
print(f"Debut envoi initial ({INITIAL_ROWS} lignes)...")
send_rows(df.head(INITIAL_ROWS))

# --- Boucle interactive ---
offset = INITIAL_ROWS
while offset < total_rows:
    remaining = total_rows - offset
    prompt = input(f"\n{remaining} lignes restantes. Combien envoyer ? [Entree = {next}] : ").strip()

    if prompt == "":
        n = next
    else:
        try:
            n = int(prompt)
            if n <= 0:
                print("Nombre invalide, valeur par defaut utilisee.")
                n = next
        except ValueError:
            print("Entree non reconnue, valeur par defaut utilisee.")
            n = next

    n = min(n, remaining)
    send_rows(df.iloc[offset : offset + n])
    offset += n
    print(f"Total envoye : {offset}/{total_rows}")

producer.close()
print("Tout le CSV a ete envoye.")