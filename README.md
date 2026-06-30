````markdown
# Windows Event Log UEBA Anomaly Detection System

A reproducible Windows Event/Sysmon UEBA pipeline that converts endpoint telemetry into 10-minute user-host behavioral windows, detects anomalies using an unsupervised Isolation Forest + Local Outlier Factor ensemble, enriches detected anomalies with SOC investigation context, and sends evidence-pack alerts through Elasticsearch and n8n.

This repository is designed as a reproducibility package. It contains source code, sanitized configuration templates, controlled replay scripts, and technical documentation. It does not include private credentials, real environment-specific values, raw logs, generated CSV outputs, or model artifacts.

---

## DOI

This repository is archived on Zenodo:

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.21080631.svg)](https://doi.org/10.5281/zenodo.21080631)

To cite all versions of this reproducibility package, use the concept DOI:

```text
10.5281/zenodo.21080631
````

A new Zenodo version DOI may be generated when a new GitHub release is archived. The concept DOI remains the stable citation target for the complete software package across versions.

---

## Main Contributions

* Windows Event Log and Sysmon data collection pipeline.
* Dataset-builder layer for 10-minute user-host behavior aggregation.
* Security-focused behavioral feature schema.
* Unsupervised Isolation Forest + Local Outlier Factor anomaly detection ensemble.
* Strict SOC-oriented final decision layer to reduce weak single-model anomaly promotion.
* SOC enrichment with priority scoring, top features, MITRE ATT&CK-aligned investigation indicators, and raw-log investigation queries.
* Elasticsearch anomaly indexing and n8n evidence-pack alerting.
* Controlled replay validation script for repeatable endpoint behavior testing.
* Sanitized Winlogbeat and Logstash configuration templates for reproducible deployment.

---

## Architecture

```text
Windows Event Logs + Sysmon
        ↓
Winlogbeat
        ↓
Logstash
        ↓
Elasticsearch raw telemetry index
        ↓
src/data_collection/pull.py
        ↓
src/preprocessing/feature_engineering.py
        ↓
behavior_dataset.csv
        ↓
src/training_testing/train_model.py
        ↓
src/training_testing/detect_anomaly.py
        ↓
model_results.csv
        ↓
src/training_testing/extract_anomalies.py
        ↓
anomalies.csv
        ↓
src/ingestion/send_anomalies_to_elastic.py
        ↓
ueba-anomalies Elasticsearch index
        ↓
n8n evidence-pack alert
        ↓
SOC analyst review
```

---

## Repository Structure

```text
configs/      Sanitized Winlogbeat, Logstash, and n8n templates
docs/         Technical documentation and methodology walkthrough
scripts/      Windows automation and controlled replay validation scripts
src/          Source code for data collection, preprocessing, training, detection, and ingestion
```

---

## Key Components

| Component                                                     | Purpose                                                                                   |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `src/data_collection/pull.py`                                 | Retrieves raw Windows/Sysmon telemetry from Elasticsearch                                 |
| `src/preprocessing/feature_engineering.py`                    | Converts raw events into 10-minute user-host behavior windows                             |
| `src/training_testing/train_model.py`                         | Trains the scaler, Isolation Forest, and LOF models                                       |
| `src/training_testing/detect_anomaly.py`                      | Scores behavior rows, applies the strict SOC decision layer, and enriches final anomalies |
| `src/training_testing/extract_anomalies.py`                   | Extracts final anomaly rows into an investigation queue                                   |
| `src/ingestion/send_anomalies_to_elastic.py`                  | Sends enriched anomalies to Elasticsearch and n8n                                         |
| `scripts/trigger_ueba_anomaly.bat`                            | Generates controlled endpoint activity for validation                                     |
| `configs/winlogbeat.template.yml`                             | Sanitized Winlogbeat collection template                                                  |
| `configs/logstash-single-active-beats-pipeline.template.conf` | Sanitized Logstash routing template                                                       |

---

## Configuration

This repository uses sanitized configuration templates. Local credentials, private IP addresses, webhook URLs, certificates, hostnames, usernames, and environment-specific paths should be stored only in private local files.

Start from:

```text
config.template.py
```

Create a private local copy named:

```text
config.py
```

Then fill in the local runtime values:

```python
ELASTIC_HOST = "https://<ELASTICSEARCH_HOST>:9200"
ELASTIC_USER = "<ELASTIC_USERNAME>"
ELASTIC_PASSWORD = "<ELASTIC_PASSWORD>"

RAW_INDEX_NAME = "winlogbeat-whatever"
ANOMALY_INDEX_NAME = "ueba-anomalies"

N8N_WEBHOOK_PRODUCTION_URL = "http://<N8N_HOST>:5678/webhook/<WEBHOOK_ID>"

VERIFY_CERTS = False
```

The local `config.py` file is ignored by Git and should never be committed.

---

## Logstash Routing Setup

This project expects Windows Event Log and Sysmon telemetry to be routed into one raw Elasticsearch telemetry index:

```text
winlogbeat-whatever
```

During validation, a routing issue was identified where more than one Logstash `.conf` file existed under:

```text
/etc/logstash/conf.d/
```

Logstash loads all `.conf` files in this directory as one combined pipeline. If multiple files contain Beats inputs or Elasticsearch outputs, the same Winlogbeat events may be routed to multiple indices. This can make feature extraction inconsistent and may also create duplicate event ingestion if multiple outputs write to the same index.

The final recommended setup is to keep one active Beats pipeline only.

Use:

```text
configs/logstash-single-active-beats-pipeline.template.conf
```

Disable duplicate Logstash configs by renaming them, for example:

```bash
sudo mv /etc/logstash/conf.d/winlogbeat.conf /etc/logstash/conf.d/winlogbeat.conf.disabled
```

Then test and restart Logstash:

```bash
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
sudo systemctl restart logstash
sudo systemctl status logstash
```

In the final setup:

* Winlogbeat logs are routed to `winlogbeat-whatever`.
* Filebeat logs are routed to daily `nginx-logs-YYYY.MM.dd` indices.
* Duplicate indexing is avoided.
* The Python feature engineering layer consistently pulls from the configured raw telemetry index.

---

## Feature Engineering

Raw Windows/Sysmon telemetry is aggregated into 10-minute behavior windows using:

```text
user_name
host_name
window_start
```

The behavioral feature schema includes authentication, credential access, process execution, shell activity, parent-process suspicion, network activity, file creation, and temporal behavior.

Example features include:

```text
successful_login_count
failed_login_count
failed_success_ratio
credential_access_count
credential_access_volume
process_creation_count
unique_process_count
powershell_exec_count
cmd_exec_count
shell_ratio
suspicious_parent_count
network_connection_count
file_creation_count
suspicious_file_creation_count
unique_login_types
activity_hour
weekend_activity
```

---

## Model Design

The anomaly detection layer uses an unsupervised ensemble:

```text
Isolation Forest + Local Outlier Factor
```

The model is trained on engineered behavior windows after scaling features with `StandardScaler`.

The detection layer produces:

```text
if_anomaly
lof_anomaly
ensemble_votes
ensemble_score
final_anomaly
detection_reason
severity
```

A strict SOC decision layer is applied after ML scoring. A behavior window is promoted to a final anomaly only when it satisfies one of the following:

1. Isolation Forest and LOF both agree, and the row has enough priority/security context.
2. At least one model flags the row, and the row contains strong security evidence.

This reduces weak single-model anomaly promotion while keeping security-relevant behavior detectable.

---

## SOC Enrichment

Final anomalies are enriched with analyst-facing investigation context:

```text
priority_score
priority_level
priority_reason
top_features
mitre_aligned_indicators
investigation_query
raw_index
window_end
```

The MITRE ATT&CK-aligned indicators are investigation hints only. They do not claim confirmed attack attribution.

---

## Controlled Replay Validation

The repository includes a controlled replay script for repeatable endpoint behavior validation:

```text
scripts/trigger_ueba_anomaly.bat
```

The validation script generates five scenarios:

1. Failed-login burst.
2. Suspicious file creation.
3. CMD execution burst.
4. PowerShell execution burst.
5. Mixed shell and file activity.

The scenarios are separated by 12-minute waiting periods. This is intentional because the dataset builder aggregates behavior into 10-minute user-host windows. Separating the scenarios helps produce cleaner validation windows and avoids mixing multiple behaviors into the same aggregation window.

After running the script, wait around five additional minutes to allow Winlogbeat, Logstash, and Elasticsearch to finish ingesting events. Then run:

```powershell
python -m src.preprocessing.feature_engineering
python .\src\training_testing\detect_anomaly.py
python .\src\training_testing\extract_anomalies.py
```

For normal operation, `SCORING_MODE` in `detect_anomaly.py` should be:

```python
SCORING_MODE = "new"
```

For full historical rescoring or controlled replay evaluation, use:

```python
SCORING_MODE = "all"
```

Then change it back to `"new"` afterward.

---

## Final Controlled Replay Results

After correcting the Logstash routing setup and rescoring the behavior dataset, the final evaluation contained:

| Metric                           |  Value |
| -------------------------------- | -----: |
| Total behavior windows           |    472 |
| Final anomalies                  |    114 |
| Anomaly rate                     | 24.15% |
| Normal windows                   |    358 |
| Model vote high priority         |    100 |
| Security rule model supported    |     14 |
| Isolation Forest flagged windows |    116 |
| LOF flagged windows              |    300 |
| IF + LOF agreement windows       |    116 |
| LOF-only flagged windows         |    184 |

Controlled replay scenario outcomes:

| Scenario                              | Result                    | Main Evidence                                                                                                              |
| ------------------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Failed-login burst                    | Detected                  | `failed_login_count = 15`, `security_rule_model_supported`                                                                 |
| CMD-only burst                        | LOF flagged, not promoted | `cmd_exec_count = 60`, single-model evidence only                                                                          |
| PowerShell + suspicious file creation | Detected                  | `powershell_exec_count = 120`, `file_creation_count = 60`, `suspicious_file_creation_count = 60`                           |
| Mixed shell + file activity           | Detected                  | `cmd_exec_count = 200`, `powershell_exec_count = 100`, `file_creation_count = 200`, `suspicious_file_creation_count = 200` |

The CMD-only scenario was flagged by LOF but was not promoted to a final anomaly. This shows that the strict SOC decision layer does not blindly promote every single-model deviation. Instead, final anomalies require either high-priority IF–LOF agreement or model-supported security evidence.

---

## Usage Workflow

A typical run follows this order:

```powershell
python -m src.preprocessing.feature_engineering
python .\src\training_testing\train_model.py
python .\src\training_testing\detect_anomaly.py
python .\src\training_testing\extract_anomalies.py
python .\src\ingestion\send_anomalies_to_elastic.py
```

For scheduled operation, the intended flow is:

```text
1. Pull recent Windows/Sysmon logs.
2. Build or update 10-minute behavioral windows.
3. Retrain periodically.
4. Score only new behavior windows.
5. Extract final anomalies.
6. Send enriched anomaly evidence to Elasticsearch/n8n.
7. Review alerts from the SOC investigation queue.
```

---

## Documentation

The full technical walkthrough is available in:

```text
docs/full_project_walkthrough.md
```

The documentation explains the architecture, ELK pipeline, data collection layer, dataset builder, feature engineering, model design, SOC enrichment, alerting workflow, controlled validation, and automation setup.

---

## Security and Privacy Notice

This repository intentionally excludes:

```text
real credentials
private IP addresses
webhook URLs
private config files
raw logs
generated CSV outputs
model artifacts
private hostnames
local usernames
environment-specific file paths
```

The files included here are intended to document and reproduce the system architecture without exposing private runtime values.

---

## Citation

If you use this architecture, code, configuration templates, dataset-builder design, SOC enrichment layer, controlled replay method, or documentation, please cite this repository and the associated Zenodo archive.

```bibtex
@software{windows_eventlog_ueba_2026,
  title = {Windows Event Log UEBA Anomaly Detection System},
  year = {2026},
  version = {1.0.0},
  doi = {10.5281/zenodo.21080631},
  url = {https://github.com/<OWNER>/<REPOSITORY>}
}
```

Replace `<OWNER>/<REPOSITORY>` with the repository location when citing a fork or local deployment.

---

## License

This project is released under the MIT License.

```
```
