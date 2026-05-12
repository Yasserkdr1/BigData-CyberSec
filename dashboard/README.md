# Dashboard CyberSec Lambda SOC 

Cette version sépare le dashboard en deux parties :

- `app.py` : backend Flask, routes API, lecture Cassandra et HBase.
- `templates/index.html` : structure HTML de l'interface.
- `static/css/style.css` : style graphique du dashboard.
- `static/js/dashboard.js` : logique frontend, appels `fetch`, graphiques Chart.js et interactions.

## Lancement

Depuis le dossier `dashboard` :

```bash
pip install -r requirements.txt
python app.py
```

Puis ouvrir :

```text
http://localhost:5000
```

## Dépendances système nécessaires

Avant de lancer le dashboard, vérifier que :

- Cassandra est accessible sur `127.0.0.1:9042`.
- HBase Thrift est accessible sur `127.0.0.1:9090`.
- Les tables HBase Batch existent et sont remplies.
- La table Cassandra `cybersec.realtime_alerts_live` existe et reçoit les alertes Speed.

## Routes principales

- `/` : interface web.
- `/api/alerts` : alertes live depuis Cassandra.
- `/api/batch/analytics` : statistiques Batch depuis HBase.
- `/api/threat/ip/<ip>` : fiche d'investigation d'une IP, combinant HBase et Cassandra.
