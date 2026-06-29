# Windows Event Log UEBA Anomaly Detection System

A reproducible Windows Event/Sysmon UEBA pipeline that converts endpoint telemetry into 10-minute user-host behavioral windows, detects anomalies using an unsupervised Isolation Forest + Local Outlier Factor ensemble, enriches detected anomalies with SOC investigation context, and sends evidence-pack alerts through Elasticsearch and n8n.

## DOI

This repository is archived on Zenodo:

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21033241.svg)](https://doi.org/10.5281/zenodo.21033241)

To cite all versions of this reproducibility package, use:

```text
10.5281/zenodo.21033241
```

## Main Contributions

* Windows/Sysmon data collection and dataset-builder layer.
* Security-focused behavioral feature schema.
* IF + LOF unsupervised anomaly detection ensemble.
* SOC enrichment with priority scoring, top features, MITRE ATT&CK-aligned indicators, and raw-log investigation queries.
* Elasticsearch alert indexing and n8n evidence-pack alerting.
* Controlled replay validation and scheduled automation.

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
```

## Key Components

| Component                                    | Purpose                                                         |
| -------------------------------------------- | --------------------------------------------------------------- |
| `src/data_collection/pull.py`                | Retrieves raw Windows/Sysmon telemetry from Elasticsearch       |
| `src/preprocessing/feature_engineering.py`   | Converts raw events into 10-minute user-host behavior windows   |
| `src/training_testing/train_model.py`        | Trains the scaler, Isolation Forest, and LOF models             |
| `src/training_testing/detect_anomaly.py`     | Scores behavior rows and enriches final anomalies               |
| `src/training_testing/extract_anomalies.py`  | Extracts final anomaly rows into an investigation queue         |
| `src/ingestion/send_anomalies_to_elastic.py` | Exports enriched anomalies to Elasticsearch and n8n             |
| `scripts/trigger_ueba_anomaly.bat`           | Generates controlled suspicious-looking behavior for validation |

## Documentation

The full technical walkthrough is available in:

```text
docs/full_project_walkthrough.md
```

This walkthrough explains the architecture, ELK pipeline, data collection layer, dataset builder, feature engineering, model design, SOC enrichment, alerting workflow, controlled validation, and automation setup.

## Configuration

This repository uses sanitized configuration templates. Local credentials, private IP addresses, webhook URLs, certificates, and environment-specific values should be supplied through a private configuration file.

Start from:

```text
src/data_collection/config.template.py
```

Create a local private copy named:

```text
config.py
```

Then fill in the required local values.

## Security and Privacy Notice

This repository intentionally excludes real credentials, webhook URLs, private configuration files, full raw logs, full CSV outputs, model artifacts, and private environment-specific paths.

The files included here are intended to document and reproduce the system architecture without exposing private runtime values.

## Citation

If you use this architecture, code, configuration templates, dataset-builder design, SOC enrichment layer, controlled replay method, or documentation, please cite this repository and the associated paper.

```bibtex
@software{mostafa_ueba_2026,
  author = {Mostafa, Yehia},
  title = {Windows Event Log UEBA Anomaly Detection System},
  year = {2026},
  version = {1.0.0},
  doi = {10.5281/zenodo.21033241},
  url = {https://github.com/YehiaAshraf5050/windows-eventlog-ueba-anomaly-detection}
}
```

## License

This project is released under the MIT License.
