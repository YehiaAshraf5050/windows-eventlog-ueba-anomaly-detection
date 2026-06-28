# Windows Event Log UEBA Anomaly Detection System

A reproducible Windows Event/Sysmon UEBA pipeline that converts endpoint telemetry into 10-minute user-host behavioral windows, detects anomalies using an unsupervised Isolation Forest + Local Outlier Factor ensemble, enriches detected anomalies with SOC investigation context, and sends evidence-pack alerts through Elasticsearch and n8n.

## Main Contributions

- Windows/Sysmon data collection and dataset-builder layer.
- Security-focused behavioral feature schema.
- IF + LOF unsupervised anomaly detection ensemble.
- SOC enrichment with priority scoring, top features, MITRE ATT&CK-aligned indicators, and raw-log investigation queries.
- Elasticsearch alert indexing and n8n evidence-pack alerting.
- Controlled replay validation and scheduled automation.

## Architecture

Windows Event Logs and Sysmon  
→ Winlogbeat  
→ Logstash  
→ Elasticsearch raw index  
→ `pull.py`  
→ `feature_engineering.py`  
→ `behavior_dataset.csv`  
→ `train_model.py`  
→ `detect_anomaly.py`  
→ `model_results.csv`  
→ `extract_anomalies.py`  
→ `anomalies.csv`  
→ `send_anomalies_to_elastic.py`  
→ `ueba-anomalies` Elasticsearch index  
→ n8n SOC evidence-pack alert

## Repository Structure

```text
configs/      Sanitized Winlogbeat, Logstash, and n8n templates
docs/         Full documentation and methodology walkthrough
scripts/      Sanitized Windows automation scripts
src/          Source code for data collection, preprocessing, training, detection, and ingestion
