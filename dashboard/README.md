# CyberSec Lambda SOC Dashboard

This version separates the dashboard into two parts:

- `app.py`: Flask backend, API routes, Cassandra and HBase reads.
- `templates/index.html`: HTML structure of the interface.
- `static/css/style.css`: Dashboard graphical styling.
- `static/js/dashboard.js`: Frontend logic, `fetch` calls, Chart.js graphs, and interactions.

## Launch

From the `dashboard` folder:

```bash
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://localhost:5000
```

## Required System Dependencies

Before launching the dashboard, ensure that:

- Cassandra is accessible at `127.0.0.1:9042`.
- HBase Thrift is accessible at `127.0.0.1:9090`.
- The HBase batch tables exist and are populated.
- The Cassandra table `cybersec.realtime_alerts_live` exists and receives Speed layer alerts.

## Main Routes

- `/`: Web interface.
- `/api/alerts`: Live alerts from Cassandra.
- `/api/batch/analytics`: Batch statistics from HBase.
- `/api/threat/ip/<ip>`: IP investigation sheet, combining HBase and Cassandra data.
