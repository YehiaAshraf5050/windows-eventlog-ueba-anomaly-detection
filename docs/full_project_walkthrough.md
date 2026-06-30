````markdown
# Full Project Walkthrough

This document provides the full technical walkthrough for the **Windows Event Log UEBA Anomaly Detection System**. It explains the current system architecture, ELK-based telemetry pipeline, data collection layer, dataset-building process, feature engineering, unsupervised anomaly detection, strict SOC decision logic, SOC enrichment, Elasticsearch alert indexing, n8n alerting, controlled replay validation, and scheduled automation.

The goal of this walkthrough is to make the project understandable and reproducible for readers who want to rebuild or extend the architecture in their own lab environment.

---

# 1. Project Overview

This project implements a Windows endpoint User and Entity Behavior Analytics pipeline for detecting abnormal user-host behavior using Windows Event Logs, Sysmon telemetry, Elasticsearch, Python feature engineering, unsupervised machine learning, and n8n alerting.

The system converts raw Windows/Sysmon events into 10-minute user-host behavior windows. Each behavior window is scored by an unsupervised anomaly detection ensemble using Isolation Forest and Local Outlier Factor. The scored rows are then passed through a strict SOC-oriented final decision layer before final anomalies are enriched with investigation metadata.

The final output is an enriched anomaly record stored in an Elasticsearch alert index and optionally sent to n8n for SOC-style evidence-pack notification.

---

# 2. Main Contributions

The project contributes the following technical components:

1. A Windows/Sysmon telemetry pipeline using Winlogbeat, Logstash, and Elasticsearch.
2. A data collection layer that retrieves raw telemetry from Elasticsearch instead of relying on manual CSV exports.
3. A dataset-builder layer that converts raw endpoint events into 10-minute user-host behavior windows.
4. A security-focused behavioral feature schema covering authentication, credential activity, process execution, shell usage, parent-child process behavior, network activity, file creation, and time context.
5. An unsupervised anomaly detection ensemble using Isolation Forest and Local Outlier Factor.
6. A strict SOC-oriented final decision layer that reduces weak single-model anomaly promotion.
7. A SOC enrichment layer that adds priority score, priority level, priority reason, top features, raw-log investigation query, raw index, and MITRE ATT&CK-aligned behavioral indicators.
8. An Elasticsearch anomaly index that stores compact investigation records for SOC review.
9. An n8n alerting workflow that can generate SOC-style evidence-pack summaries.
10. A controlled replay script that generates repeatable suspicious-looking endpoint behavior for validation.
11. A scheduled automation design using Windows Task Scheduler, Docker Desktop, VM startup/shutdown scripts, SSH, and batch files.
12. Sanitized configuration templates for reproducible deployment without exposing private runtime values.

---

# 3. System Architecture

The complete pipeline is:

```text
Windows Event Logs and Sysmon
→ Winlogbeat
→ Logstash
→ Elasticsearch raw telemetry index
→ pull.py
→ feature_engineering.py
→ behavior_dataset.csv
→ train_model.py
→ model_artifacts_latest.joblib
→ detect_anomaly.py
→ model_results.csv
→ strict SOC decision layer
→ SOC enrichment layer
→ extract_anomalies.py
→ anomalies.csv
→ send_anomalies_to_elastic.py
→ ueba-anomalies Elasticsearch index
→ n8n Webhook
→ SOC evidence-pack summary
→ SOC analyst review
````

## 3.1 Main Components

| Component                      | Purpose                                                                                   |
| ------------------------------ | ----------------------------------------------------------------------------------------- |
| Windows Event Logs / Sysmon    | Endpoint telemetry source                                                                 |
| Winlogbeat                     | Forwards Windows logs                                                                     |
| Logstash                       | Receives and routes logs to Elasticsearch                                                 |
| Elasticsearch raw index        | Stores original Windows/Sysmon telemetry                                                  |
| `pull.py`                      | Retrieves raw telemetry from Elasticsearch                                                |
| `feature_engineering.py`       | Builds 10-minute user-host behavior windows                                               |
| `behavior_dataset.csv`         | ML-ready behavior dataset                                                                 |
| `train_model.py`               | Trains scaler, Isolation Forest, and LOF                                                  |
| `detect_anomaly.py`            | Scores behavior rows, applies the strict SOC decision layer, and enriches final anomalies |
| `model_results.csv`            | Full scoring output, including normal and anomaly rows                                    |
| `extract_anomalies.py`         | Extracts final anomaly rows                                                               |
| `anomalies.csv`                | Alert-ready investigation queue                                                           |
| `send_anomalies_to_elastic.py` | Stores anomalies in Elasticsearch and sends n8n batch alerts                              |
| `ueba-anomalies`               | Dedicated alert index for SOC review                                                      |
| n8n                            | Optional evidence-pack alerting workflow                                                  |

---

# 4. ELK Foundation

The project uses Elasticsearch, Logstash, and Kibana as the backend SIEM-style environment.

## 4.1 Elasticsearch

Elasticsearch stores both raw telemetry and enriched anomaly records.

Two main indices are used:

| Index                 | Purpose                                                                        |
| --------------------- | ------------------------------------------------------------------------------ |
| `winlogbeat-whatever` | Generic raw Windows/Sysmon telemetry index used by the reproducibility package |
| `ueba-anomalies`      | Enriched anomaly records for SOC review                                        |

The raw index stores detailed endpoint events, while the anomaly index stores summarized investigation records created by the ML pipeline.

The raw index name is configurable through `config.py`:

```python
RAW_INDEX_NAME = "winlogbeat-whatever"
```

A user reproducing the project can replace this with any local Elasticsearch index name.

## 4.2 Logstash

Logstash is used as the ingestion and routing layer between Winlogbeat and Elasticsearch.

The final recommended setup uses **one active Beats pipeline only**. This avoids duplicate indexing and ensures that Winlogbeat events are routed consistently into the configured raw telemetry index.

The sanitized Logstash template is:

```text
configs/logstash-single-active-beats-pipeline.template.conf
```

The template receives Beats traffic on port `5044`, routes Winlogbeat events to the configured Windows telemetry index, and optionally routes Filebeat events to separate daily indices.

Recommended operational rule:

```text
Keep only one active Beats input pipeline on port 5044.
Disable old or duplicate Logstash configs by renaming them with a .disabled suffix.
```

Example:

```bash
sudo mv /etc/logstash/conf.d/winlogbeat.conf /etc/logstash/conf.d/winlogbeat.conf.disabled
```

Then test and restart Logstash:

```bash
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
sudo systemctl restart logstash
sudo systemctl status logstash
```

## 4.3 Winlogbeat

Winlogbeat collects Windows Event Logs and Sysmon telemetry and forwards them to Logstash.

A reusable Winlogbeat configuration template is provided in:

```text
configs/winlogbeat.template.yml
```

The configuration includes Windows Security, System, Application, Sysmon, and optional PowerShell event channels.

---

# 5. Configuration and Reproducibility Design

The project separates implementation logic from environment-specific values. This makes the repository reusable across different machines, networks, and lab environments.

Instead of hardcoding local credentials, private IP addresses, webhook URLs, hostnames, or local file paths directly into the code, the project uses configuration templates.

## 5.1 Configuration Template

The repository includes:

```text
config.template.py
```

This file defines the required configuration variables:

```text
ELASTIC_HOST
ELASTIC_USER
ELASTIC_PASSWORD
RAW_INDEX_NAME
ANOMALY_INDEX_NAME
N8N_WEBHOOK_PRODUCTION_URL
VERIFY_CERTS
```

A user who wants to reproduce the project can copy the template into a private `config.py` file and fill in their own local values.

Example local configuration:

```python
ELASTIC_HOST = "https://<ELASTICSEARCH_HOST>:9200"
ELASTIC_USER = "<ELASTIC_USERNAME>"
ELASTIC_PASSWORD = "<ELASTIC_PASSWORD>"

RAW_INDEX_NAME = "winlogbeat-whatever"
ANOMALY_INDEX_NAME = "ueba-anomalies"

N8N_WEBHOOK_PRODUCTION_URL = "http://<N8N_HOST>:5678/webhook/<WEBHOOK_ID>"

VERIFY_CERTS = False
```

The private `config.py` file should never be committed.

## 5.2 Why Templates Are Used

Configuration templates provide two benefits:

1. **Reproducibility:** readers can see exactly which configuration values are needed.
2. **Portability:** the same code can run in different environments by changing only the local configuration file.

This design keeps the source code independent from one specific lab machine, username, network, or organization.

---

# 6. Data Collection Layer

The data collection layer retrieves raw Windows/Sysmon events from Elasticsearch before feature engineering.

## 6.1 Purpose of `pull.py`

`pull.py` prevents the project from depending on manual CSV exports from Kibana. Instead, it programmatically connects to Elasticsearch, queries the configured raw telemetry index, and provides raw event records to the dataset-builder layer.

The data flow is:

```text
Elasticsearch raw index
→ pull.py
→ raw event records
→ feature_engineering.py
→ behavior_dataset.csv
```

This makes the dataset construction process more reproducible because raw telemetry is pulled through code rather than manually exported.

## 6.2 Relationship Between `pull.py` and `feature_engineering.py`

`pull.py` handles retrieval.
`feature_engineering.py` handles transformation.

| Layer           | Script                   | Responsibility                                       |
| --------------- | ------------------------ | ---------------------------------------------------- |
| Data collection | `pull.py`                | Query Elasticsearch and retrieve raw telemetry       |
| Dataset builder | `feature_engineering.py` | Convert raw telemetry into ML-ready behavior windows |

---

# 7. Dataset Builder and Feature Engineering

Raw logs are not directly suitable for machine learning because they are high-volume event records with many fields and inconsistent meaning across event types.

The feature engineering layer converts raw Windows/Sysmon telemetry into structured behavior windows.

## 7.1 Behavior Row Definition

Each row represents:

```text
one user + one host + one 10-minute time window
```

The identity columns are:

```text
user_name
host_name
window_start
```

These columns are kept for interpretation and investigation, but they are not used as ML training features.

## 7.2 Feature Groups

| Category            | Features                                                                                     | Purpose                                                 |
| ------------------- | -------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| Identity            | `user_name`, `host_name`, `window_start`                                                     | Locate the behavior window                              |
| Login behavior      | `successful_login_count`, `failed_login_count`, `failed_success_ratio`, `unique_login_types` | Detect unusual authentication behavior                  |
| Credential behavior | `credential_access_count`, `credential_access_volume`, `credential_volume_per_read`          | Capture abnormal credential-related activity            |
| Process behavior    | `process_creation_count`, `unique_process_count`, `process_diversity_ratio`                  | Detect abnormal execution volume and process diversity  |
| Shell behavior      | `powershell_exec_count`, `cmd_exec_count`, `shell_ratio`                                     | Detect shell-heavy activity                             |
| Parent behavior     | `suspicious_parent_count`                                                                    | Detect suspicious parent-child process behavior         |
| Network behavior    | `network_connection_count`, `network_per_process`                                            | Capture network activity relative to execution          |
| File behavior       | `file_creation_count`, `suspicious_file_creation_count`, `file_per_process`                  | Detect file creation bursts and suspicious file staging |
| Time context        | `activity_hour`, `weekend_activity`                                                          | Add temporal context                                    |

## 7.3 Event Parsing Logic

The dataset builder extracts values from Windows and Sysmon fields that may differ by event type.

Important field sources include:

```text
winlog.event_data.SubjectUserName
winlog.event_data.TargetUserName
winlog.event_data.User
winlog.event_data.Image
winlog.event_data.ParentImage
winlog.event_data.TargetFilename
event.code
event.action
host.name
@timestamp
```

This allows the feature engineering layer to capture authentication activity, process execution, PowerShell/CMD activity, and file creation events from the raw telemetry.

---

# 8. Feature Dictionary

| Feature                          | Definition                                                      | Security meaning                                    |
| -------------------------------- | --------------------------------------------------------------- | --------------------------------------------------- |
| `successful_login_count`         | Count of successful logon events in the window                  | Measures normal authentication activity             |
| `failed_login_count`             | Count of failed logon events in the window                      | Detects failed login bursts                         |
| `failed_success_ratio`           | Failed logins divided by successful logins plus one             | Highlights abnormal authentication failure behavior |
| `credential_access_count`        | Count of credential-related events                              | Captures possible credential access behavior        |
| `credential_access_volume`       | Total credential-related event volume                           | Measures intensity of credential activity           |
| `credential_volume_per_read`     | Credential volume divided by credential event count plus one    | Captures credential activity density                |
| `process_creation_count`         | Count of process creation events                                | Detects execution bursts                            |
| `unique_process_count`           | Number of unique process names                                  | Measures process diversity                          |
| `process_diversity_ratio`        | Unique processes divided by process creation count plus one     | Detects unusual process variety                     |
| `powershell_exec_count`          | Count of PowerShell executions                                  | Captures scripting behavior                         |
| `cmd_exec_count`                 | Count of CMD executions                                         | Captures command-line behavior                      |
| `shell_ratio`                    | PowerShell and CMD executions divided by process count plus one | Detects shell-heavy behavior                        |
| `suspicious_parent_count`        | Count of suspicious parent-child process patterns               | Captures abnormal execution chains                  |
| `network_connection_count`       | Count of network connection events                              | Detects network activity bursts                     |
| `network_per_process`            | Network connections divided by process count plus one           | Measures network activity relative to execution     |
| `file_creation_count`            | Count of file creation events                                   | Detects file creation bursts                        |
| `suspicious_file_creation_count` | Count of suspicious script/executable file creations            | Captures possible tool staging                      |
| `file_per_process`               | File creations divided by process count plus one                | Measures file activity relative to execution        |
| `unique_login_types`             | Number of unique Windows logon types                            | Detects unusual authentication diversity            |
| `activity_hour`                  | Hour extracted from the window timestamp                        | Adds time-of-day context                            |
| `weekend_activity`               | Binary flag for weekend activity                                | Adds off-hours context                              |

---

# 9. Machine Learning Pipeline

The ML pipeline starts after `behavior_dataset.csv` has been created.

Since the dataset does not contain complete labels such as `attack` and `normal`, the system uses unsupervised anomaly detection.

The goal is not to classify known attacks directly. Instead, the model learns the shape of mostly normal behavior and flags behavior windows that strongly deviate from that baseline.

## 9.1 Training

`train_model.py` performs the following steps:

1. Load `behavior_dataset.csv`.
2. Select the configured training window.
3. Exclude previously detected final anomalies from the temporary training dataframe.
4. Fit a `StandardScaler`.
5. Train Isolation Forest.
6. Train Local Outlier Factor.
7. Save trained artifacts to the model registry.

The model artifacts include:

```text
trained StandardScaler
trained Isolation Forest
trained Local Outlier Factor
feature column list
identity column list
training score ranges
training metadata
```

## 9.2 Scaling

`StandardScaler` is used because feature values have different scales. For example:

```text
weekend_activity = 0 or 1
failed_login_count = small number
process_creation_count = hundreds
file_creation_count = hundreds
```

Scaling prevents large numeric features from dominating the model.

## 9.3 Detection Models

The final anomaly detection ensemble uses:

| Model                | Purpose                              |
| -------------------- | ------------------------------------ |
| Isolation Forest     | Detects global outliers              |
| Local Outlier Factor | Detects local density-based outliers |

## 9.4 Detection Output

`detect_anomaly.py` loads the latest model artifact and scores behavior rows.

The output is:

```text
model_results.csv
```

This file contains both normal and anomalous rows.

Important columns include:

```text
if_anomaly
lof_anomaly
if_score_scaled
lof_score_scaled
ensemble_votes
ensemble_score
final_anomaly
detection_reason
severity
```

## 9.5 Strict SOC Final Decision Layer

After ML scoring, the system applies a stricter SOC-oriented final decision layer.

A behavior window is promoted to:

```text
final_anomaly = 1
```

only if one of the following conditions is met:

1. Isolation Forest and LOF both agree, and the row has enough priority/security context.
2. At least one model flags the row, and the row contains strong security evidence.

Strong security evidence includes failed-login bursts, suspicious file creation, shell-heavy execution, combined CMD/PowerShell activity, or suspicious parent-process behavior.

This layer reduces weak single-model anomaly promotion, especially single-model statistical deviations that do not contain strong security evidence.

---

# 10. SOC Enrichment Layer

The project goes beyond binary anomaly detection by adding SOC-oriented enrichment fields.

These fields make the anomaly easier to investigate and prioritize.

## 10.1 Enrichment Fields

| Field                      | Purpose                                             |
| -------------------------- | --------------------------------------------------- |
| `window_end`               | End of the 10-minute anomaly window                 |
| `raw_index`                | Source Elasticsearch index containing original logs |
| `investigation_query`      | Query template for retrieving raw logs              |
| `priority_score`           | Numeric SOC triage score                            |
| `priority_level`           | Human-readable priority level                       |
| `priority_reason`          | Explanation of why the priority was assigned        |
| `top_features`             | Highest contributing behavioral feature values      |
| `mitre_aligned_indicators` | ATT&CK-aligned investigation context                |

## 10.2 Raw-Log Investigation Metadata

Each anomaly includes enough metadata to return to the original raw telemetry:

```text
user_name
host_name
window_start
window_end
raw_index
investigation_query
```

The anomaly record does not replace the raw logs. It acts as a compact pointer to the relevant raw Windows/Sysmon events.

## 10.3 MITRE ATT&CK-Aligned Indicators

The system maps selected abnormal feature groups to MITRE ATT&CK-aligned investigation hints.

These mappings do not prove that a specific attack technique occurred. They are used only to guide analyst investigation.

---

# 11. Anomaly Extraction and Export

## 11.1 `extract_anomalies.py`

`extract_anomalies.py` reads:

```text
model_results.csv
```

and keeps only rows where:

```text
final_anomaly = 1
```

The output is:

```text
anomalies.csv
```

This file represents the alert-ready investigation queue.

## 11.2 `send_anomalies_to_elastic.py`

`send_anomalies_to_elastic.py` reads:

```text
anomalies.csv
```

Then it:

1. Converts each anomaly row into a JSON document.
2. Generates a stable document ID using `user_name + host_name + window_start`.
3. Stores the document in the `ueba-anomalies` Elasticsearch index.
4. Sends a batch of new anomalies to n8n.
5. Updates alert status after successful webhook delivery.

The stable document ID prevents duplicate anomaly records and duplicate alerts.

---

# 12. n8n Alerting Workflow

n8n provides the automated notification layer.

The workflow receives a JSON batch from Python and generates a SOC-style HTML summary.

## 12.1 Workflow Nodes

| Node             | Purpose                                                 |
| ---------------- | ------------------------------------------------------- |
| Webhook          | Receives anomaly batch                                  |
| AI Agent         | Converts JSON anomaly batch into SOC-style HTML summary |
| Edit Fields      | Cleans the HTML output                                  |
| Email/Gmail node | Sends the final SOC alert email                         |

## 12.2 Prompt Safety

The n8n AI prompt instructs the model to:

* Use only the provided anomaly records.
* Not invent users, hosts, timestamps, anomaly types, or counts.
* Return raw HTML only.
* Use cautious SOC language.
* Include priority score and priority level.
* Include top features and MITRE-aligned indicators as investigation context.
* Include the investigation query for raw-log review.

The prompt is stored in:

```text
configs/n8n-alert-prompt.md
```

---

# 13. Controlled Replay Validation

A controlled replay script is included to validate that the system can detect abnormal behavior generated after training.

The script is:

```text
scripts/trigger_ueba_anomaly.bat
```

## 13.1 Simulated Behavior

The validation script generates five scenarios separated by 12-minute waiting periods:

| Scenario | Behavior                      | Purpose                                        |
| -------- | ----------------------------- | ---------------------------------------------- |
| 1        | Failed-login burst            | Tests failed authentication behavior           |
| 2        | Suspicious file creation      | Tests script/executable file creation features |
| 3        | CMD execution burst           | Tests command-line execution behavior          |
| 4        | PowerShell execution burst    | Tests scripting behavior                       |
| 5        | Mixed shell and file activity | Tests combined suspicious behavior             |

The 12-minute separation is intentional because the dataset builder aggregates events into 10-minute user-host behavior windows. Separating the scenarios produces cleaner validation windows and avoids mixing all behaviors into one window.

## 13.2 Expected Feature Impact

| Scenario                      | Expected feature impact                                                                                           |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Failed-login burst            | `failed_login_count`, `failed_success_ratio`                                                                      |
| Suspicious file creation      | `file_creation_count`, `suspicious_file_creation_count`                                                           |
| CMD execution burst           | `cmd_exec_count`, `process_creation_count`, `shell_ratio`                                                         |
| PowerShell execution burst    | `powershell_exec_count`, `process_creation_count`, `shell_ratio`                                                  |
| Mixed shell and file activity | `cmd_exec_count`, `powershell_exec_count`, `file_creation_count`, `suspicious_file_creation_count`, `shell_ratio` |

## 13.3 Final Controlled Replay Results

The final evaluation contained:

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

## 13.4 Validation Meaning

The controlled replay test is not a real attack and is not a full labeled benchmark. It is a practical validation test showing that the pipeline can detect suspicious-looking behavior generated after training and convert it into enriched alert records.

Because the dataset is unlabeled, the evaluation does not claim precision, recall, F1-score, or attack-classification accuracy.

---

# 14. Automation and Scheduling

The automation layer turns the project from a manual pipeline into a scheduled lab system.

Scripts are stored in:

```text
scripts/
```

Automation documentation is stored in:

```text
docs/automation_setup.md
```

## 14.1 Automation Scripts

| Script                               | Purpose                                                     |
| ------------------------------------ | ----------------------------------------------------------- |
| `start_docker_desktop.bat`           | Starts Docker Desktop and n8n                               |
| `start_ubuntu_server_vm.bat`         | Starts the SIEM VM                                          |
| `training_pipeline_every_3_days.bat` | Runs feature engineering and model training                 |
| `daily_detection_pipeline.bat`       | Runs feature engineering, detection, extraction, and export |
| `backup_ueba_project.bat`            | Creates backups of important project outputs                |
| `shutdown_ubuntu_server_vm.bat`      | Shuts down the SIEM VM safely through SSH                   |
| `stop_n8n_container.bat`             | Stops only the n8n container                                |

## 14.2 Scheduled Plan

| Time    | Script                               | Frequency      | Purpose                       |
| ------- | ------------------------------------ | -------------- | ----------------------------- |
| 7:45 PM | `start_docker_desktop.bat`           | Daily          | Starts Docker Desktop and n8n |
| 8:00 PM | `start_ubuntu_server_vm.bat`         | Daily          | Starts the SIEM VM            |
| 8:10 PM | `training_pipeline_every_3_days.bat` | Every 3 days   | Retrains the ML model         |
| 8:40 PM | `daily_detection_pipeline.bat`       | Daily          | Runs detection and alerting   |
| 9:00 PM | `backup_ueba_project.bat`            | Daily          | Backs up outputs              |
| 9:15 PM | `shutdown_ubuntu_server_vm.bat`      | Daily          | Safely shuts down the SIEM VM |
| 9:30 PM | `stop_n8n_container.bat`             | Optional daily | Stops n8n container           |

## 14.3 Task Scheduler Design

The Windows Task Scheduler setup is designed to make the pipeline run without daily manual execution.

Recommended task settings include:

```text
Run with highest privileges
Wake the computer to run this task
Run task as soon as possible after a scheduled start is missed
Start in: C:\Scripts
```

For Docker Desktop and VM startup tasks, the workflow may use:

```text
Run only when user is logged on
```

because graphical applications may require an active Windows session.

---

# 15. Repository and Reproducibility Package

The public repository is organized as a reproducibility package rather than a raw project dump.

## 15.1 Repository Structure

```text
configs/      Reusable Winlogbeat, Logstash, and n8n templates
docs/         Full documentation and methodology walkthrough
scripts/      Windows automation and validation scripts
src/          Source code for data collection, preprocessing, training, detection, and ingestion
```

## 15.2 Reproducibility Approach

The repository provides the architecture, code structure, configuration templates, documentation, and scripts needed to understand and rebuild the system.

Environment-specific values are represented with placeholders so that readers can adapt the project to their own lab environment.

## 15.3 Runtime Components

A full reproduction requires:

| Component              | Role                                                 |
| ---------------------- | ---------------------------------------------------- |
| Windows machine        | Endpoint telemetry source                            |
| Sysmon                 | Detailed process, file, and network telemetry        |
| Winlogbeat             | Event forwarding                                     |
| Logstash               | Ingestion layer                                      |
| Elasticsearch          | Raw log and anomaly storage                          |
| Kibana                 | Investigation interface                              |
| Python                 | Feature engineering, training, detection, and export |
| Docker Desktop         | n8n runtime                                          |
| n8n                    | SOC alerting workflow                                |
| Windows Task Scheduler | Automation                                           |

---

# 16. Operational Security Considerations

The project uses configuration templates and placeholders to keep implementation logic separate from local runtime secrets.

This is an important operational design choice because reproducible security projects often require credentials, local IP addresses, webhook URLs, and certificates. These values are environment-specific and should be supplied by the operator during deployment rather than embedded in reusable source code.

## 16.1 Placeholder-Based Configuration

Templates use placeholders such as:

```text
<ELASTICSEARCH_HOST>
<ELASTIC_USERNAME>
<ELASTIC_PASSWORD>
<N8N_HOST>
<WEBHOOK_ID>
<LOGSTASH_SERVER_IP>
```

This allows the same repository to be reused in different environments.

## 16.2 Local Configuration File

A local deployment should create a private configuration file based on the provided template:

```text
config.template.py → config.py
```

The private `config.py` contains the operator’s local runtime values.

## 16.3 Certificate Verification

A local lab deployment may use relaxed certificate verification for Elasticsearch testing. In a production deployment, certificate verification should be enabled and the Elasticsearch CA certificate should be configured properly.

---

# 17. Evaluation Summary

The project was evaluated through:

| Evaluation method            | Purpose                                                  |
| ---------------------------- | -------------------------------------------------------- |
| Manual anomaly review        | Check whether detected rows make security sense          |
| Model agreement analysis     | Check whether both models flag the same behavior         |
| Controlled replay validation | Verify detection of generated abnormal behavior          |
| SOC enrichment review        | Confirm that alerts contain useful investigation context |

This is not a full ground-truth accuracy evaluation. True precision, recall, and F1-score require a larger labeled dataset.

## 17.1 Final Result Summary

The final controlled replay evaluation produced:

```text
Total behavior windows: 472
Final anomalies: 114
Anomaly rate: 24.15%
Normal windows: 358
Model vote high priority: 100
Security rule model supported: 14
Isolation Forest flagged windows: 116
LOF flagged windows: 300
IF + LOF agreement windows: 116
LOF-only flagged windows: 184
```

The final results should be interpreted as proof-of-concept validation rather than a benchmark accuracy score.

---

# 18. Limitations

Current limitations include:

| Limitation                                | Future improvement                                            |
| ----------------------------------------- | ------------------------------------------------------------- |
| Small lab dataset                         | Collect data from more users and hosts                        |
| No complete ground-truth labels           | Build labeled normal and suspicious test cases                |
| Credential features can be noisy          | Refine credential feature logic                               |
| Login features are sparse                 | Collect longer-term multi-user data                           |
| Limited per-user baseline                 | Add stronger per-user and per-host baselines                  |
| MITRE mappings are indicator-based        | Validate mappings with richer controlled tests                |
| No full SOC feedback loop yet             | Add analyst review statuses to guide future training          |
| Drift monitoring is not fully implemented | Add daily behavior profile monitoring and anomaly-rate trends |

---

# 19. Future Work

Future improvements include:

1. Larger multi-user and multi-host dataset.
2. Active Directory lab deployment.
3. Per-user and per-host baselines.
4. Longer training windows.
5. Drift monitoring and anomaly-rate trend charts.
6. SOC feedback loop using review statuses.
7. More controlled simulations, including parent-child process anomalies.
8. Labeled evaluation for precision, recall, and F1-score.
9. Optional formal explainability methods.
10. More robust production deployment with verified certificates and hardened secrets management.

---

# 20. Conclusion

The final system is an end-to-end Windows Event/Sysmon UEBA anomaly detection pipeline built using Elasticsearch, Python feature engineering, unsupervised machine learning, anomaly indexing, n8n alerting, and scheduled automation.

The project converts raw endpoint telemetry into behavioral windows, trains an unsupervised Isolation Forest + Local Outlier Factor ensemble, scores new behavior, applies a strict SOC-oriented final decision layer, enriches final anomalies with SOC investigation context, stores alert records in Elasticsearch, and sends SOC-style alerts through n8n.

The final version goes beyond basic anomaly scoring by adding a dataset-builder layer, raw-log investigation metadata, priority scoring, top feature explanations, MITRE ATT&CK-aligned investigation context, Elasticsearch alert indexing, n8n evidence-pack alerting, controlled replay validation, and scheduled operational automation.

This makes the project a reproducible local-lab prototype for automated Windows endpoint UEBA anomaly detection and SOC-oriented alerting.

```
```
