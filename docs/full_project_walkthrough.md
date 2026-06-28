# Full Project Walkthrough

This document provides the full technical walkthrough for the **Windows Event Log UEBA Anomaly Detection System**. It explains the system architecture, ELK-based telemetry pipeline, data collection layer, dataset-building process, feature engineering, unsupervised anomaly detection, SOC enrichment, Elasticsearch alert indexing, n8n alerting, controlled replay validation, and scheduled automation.

The goal of this walkthrough is to make the project understandable and reproducible for readers who want to study, rebuild, or extend the architecture.

Shorter focused documents are also provided in the `docs/` folder, including architecture, feature dictionary, model design, SOC enrichment, evaluation, controlled replay validation, and automation setup.

---

# 1. Project Overview

This project implements a Windows endpoint User and Entity Behavior Analytics pipeline for detecting abnormal user-host behavior using Windows Event Logs, Sysmon telemetry, Elasticsearch, Python feature engineering, unsupervised machine learning, and n8n alerting.

The system converts raw Windows/Sysmon events into 10-minute user-host behavior windows. Each behavior window is scored by an unsupervised anomaly detection ensemble using Isolation Forest and Local Outlier Factor. Final anomalies are enriched with SOC-oriented investigation metadata, priority scoring, top feature explanations, MITRE ATT&CK-aligned behavioral indicators, and raw-log investigation queries.

The final output is an enriched anomaly record stored in an Elasticsearch alert index and sent to n8n for SOC-style evidence-pack email notification.

---

# 2. Main Contributions

The project contributes the following technical components:

1. A Windows/Sysmon telemetry pipeline using Winlogbeat, Logstash, and Elasticsearch.
2. A data collection layer that retrieves raw telemetry from Elasticsearch instead of relying on manual CSV exports.
3. A dataset-builder layer that converts raw endpoint events into 10-minute user-host behavior windows.
4. A security-focused behavioral feature schema covering authentication, credential activity, process execution, shell usage, parent-child process behavior, network activity, file creation, and time context.
5. A refined unsupervised anomaly detection ensemble using Isolation Forest and Local Outlier Factor.
6. A comparative model analysis that removed One-Class SVM because it produced excessive anomaly flags.
7. A SOC-oriented enrichment layer that adds priority score, priority level, priority reason, top features, investigation query, raw index, and MITRE ATT&CK-aligned behavioral indicators.
8. An Elasticsearch anomaly index that stores compact investigation records for SOC review.
9. An n8n alerting workflow that generates SOC-style evidence-pack email summaries.
10. A controlled replay script that generates temporary suspicious-looking behavior for validation.
11. A scheduled automation design using Windows Task Scheduler, Docker Desktop, VMware, SSH, and batch files.

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
→ SOC enrichment layer
→ extract_anomalies.py
→ anomalies.csv
→ send_anomalies_to_elastic.py
→ ueba-anomalies Elasticsearch index
→ n8n Webhook
→ AI Agent evidence-pack summary
→ Gmail SOC alert
```

## 3.1 Main Components

| Component                      | Purpose                                                      |
| ------------------------------ | ------------------------------------------------------------ |
| Windows Event Logs / Sysmon    | Endpoint telemetry source                                    |
| Winlogbeat                     | Forwards Windows logs                                        |
| Logstash                       | Receives and forwards logs to Elasticsearch                  |
| Elasticsearch raw index        | Stores original Windows/Sysmon telemetry                     |
| `pull.py`                      | Retrieves raw telemetry from Elasticsearch                   |
| `feature_engineering.py`       | Builds 10-minute user-host behavior windows                  |
| `behavior_dataset.csv`         | ML-ready behavior dataset                                    |
| `train_model.py`               | Trains scaler, Isolation Forest, and LOF                     |
| `detect_anomaly.py`            | Scores behavior rows and enriches final anomalies            |
| `model_results.csv`            | Full scoring output, including normal and anomaly rows       |
| `extract_anomalies.py`         | Extracts final anomaly rows                                  |
| `anomalies.csv`                | Alert-ready investigation queue                              |
| `send_anomalies_to_elastic.py` | Stores anomalies in Elasticsearch and sends n8n batch alerts |
| `ueba-anomalies`               | Dedicated alert index for SOC review                         |
| n8n                            | Sends SOC-style email notification                           |

---

# 4. ELK Foundation

The project uses Elasticsearch, Logstash, and Kibana as the backend SIEM-style environment.

## 4.1 Elasticsearch

Elasticsearch stores both raw telemetry and enriched anomaly records.

Two main indices are used:

| Index                       | Purpose                                 |
| --------------------------- | --------------------------------------- |
| `winlogbeat-nileuniversity` | Raw Windows/Sysmon telemetry            |
| `ueba-anomalies`            | Enriched anomaly records for SOC review |

The raw index stores detailed endpoint events, while the anomaly index stores summarized investigation records created by the ML pipeline.

## 4.2 Logstash

Although Winlogbeat can send logs directly to Elasticsearch, Logstash was retained as an intermediate ingestion layer. This provides future flexibility for parsing, filtering, normalization, enrichment, and routing without modifying the endpoint collection layer.

A reusable Logstash configuration template is provided in:

```text
configs/logstash-winlogbeat.template.conf
```

This template receives Beats traffic on port `5044` and forwards it to Elasticsearch.

## 4.3 Winlogbeat

Winlogbeat collects Windows Event Logs and Sysmon telemetry and forwards them to Logstash.

A reusable Winlogbeat configuration template is provided in:

```text
configs/winlogbeat.template.yml
```

The configuration includes Windows Security, System, Application, and Sysmon event channels.

---

# 5. Configuration and Reproducibility Design

The project separates implementation logic from environment-specific values. This makes the repository reusable across different machines, networks, and lab environments.

Instead of hardcoding local credentials, IP addresses, or webhook URLs directly into the code, the project uses configuration templates.

## 5.1 Configuration Template

The repository includes:

```text
src/data_collection/config.template.py
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

## 5.2 Why Templates Are Used

Configuration templates provide two benefits:

1. **Reproducibility:** readers can see exactly which configuration values are needed.
2. **Portability:** the same code can run in different environments by changing only the local configuration file.

This design also keeps the source code independent from one specific lab machine or network setup.

---

# 6. Data Collection Layer

The data collection layer retrieves raw Windows/Sysmon events from Elasticsearch before feature engineering.

## 6.1 Purpose of `pull.py`

`pull.py` prevents the project from depending on manual CSV exports from Kibana. Instead, it programmatically connects to Elasticsearch, queries the raw telemetry index, and provides raw event records to the dataset-builder layer.

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

This separation makes the pipeline easier to understand and maintain:

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

## 7.3 Dataset Engineering Challenges

During development, several engineering issues had to be solved to make the dataset meaningful. These are included because they explain why the final feature engineering design is structured the way it is.

| Challenge                                                 | Resolution                                                           | Result                                    |
| --------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------- |
| Windows events may store usernames in different fields    | Used `SubjectUserName`, `TargetUserName`, and Sysmon `User` fallback | Better user attribution                   |
| Event codes may appear as different data types            | Normalized event codes before matching                               | More reliable login event detection       |
| UTC timestamps may not match local analyst interpretation | Converted timestamps for local interpretation where needed           | Better alignment with real activity time  |
| Sysmon action names may include additional text           | Used more flexible matching for event actions                        | More realistic process counts             |
| Some file extensions generate noisy activity              | Refined suspicious file logic                                        | Reduced misleading suspicious file counts |
| Some windows may become empty if parsing fails            | Improved attribution and event parsing                               | More useful behavioral variation          |

These design decisions are part of the dataset-builder contribution because they transform raw logs into stable behavior windows suitable for anomaly detection.

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
2. Select the most recent training window.
3. Remove known previous final anomalies from the temporary training dataframe.
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

## 9.3 Final Models

The final ensemble uses:

| Model                | Purpose                              |
| -------------------- | ------------------------------------ |
| Isolation Forest     | Detects global outliers              |
| Local Outlier Factor | Detects local density-based outliers |

One-Class SVM was tested but removed because it produced too many anomaly flags and increased alert noise.

## 9.4 Detection

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

The strongest alerts are rows where both models agree:

```text
if_anomaly = 1
lof_anomaly = 1
ensemble_votes = 2
final_anomaly = 1
```

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

The workflow receives a JSON batch from Python and generates a SOC-style HTML email summary.

## 12.1 Workflow Nodes

| Node        | Purpose                                                 |
| ----------- | ------------------------------------------------------- |
| Webhook     | Receives anomaly batch                                  |
| AI Agent    | Converts JSON anomaly batch into SOC-style HTML summary |
| Edit Fields | Cleans the HTML output                                  |
| Gmail       | Sends the final SOC alert email                         |

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

The script generates:

| Behavior                                            | Purpose                                    |
| --------------------------------------------------- | ------------------------------------------ |
| Temporary local user                                | Supports authentication testing            |
| Failed authentication attempts                      | Tests failed-login features                |
| Suspicious `.bat`, `.ps1`, `.cmd`, and `.exe` files | Tests suspicious file creation             |
| Repeated CMD execution                              | Tests command-line activity                |
| Repeated PowerShell execution                       | Tests scripting behavior                   |
| Extra text files                                    | Tests file creation volume                 |
| Cleanup                                             | Removes temporary files and temporary user |

## 13.2 Expected Feature Impact

| Feature                          | Expected effect |
| -------------------------------- | --------------- |
| `failed_login_count`             | Increase        |
| `failed_success_ratio`           | Increase        |
| `process_creation_count`         | Increase        |
| `powershell_exec_count`          | Increase        |
| `cmd_exec_count`                 | Increase        |
| `shell_ratio`                    | Increase        |
| `file_creation_count`            | Increase        |
| `suspicious_file_creation_count` | Increase        |

## 13.3 Validation Meaning

The controlled replay test is not a real attack and is not a full labeled benchmark. It is a practical validation test showing that the pipeline can detect suspicious-looking behavior generated after training and convert it into an enriched alert.

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
| `start_ubuntu_server_vm.bat`         | Starts Ubuntu SIEM VM                                       |
| `training_pipeline_every_3_days.bat` | Runs feature engineering and model training                 |
| `daily_detection_pipeline.bat`       | Runs feature engineering, detection, extraction, and export |
| `backup_ueba_project.bat`           | Creates backups of important project outputs                |
| `shutdown_ubuntu_server_vm.bat`      | Shuts down Ubuntu VM safely through SSH                     |
| `stop_n8n_container.bat`             | Stops only the n8n container                                |

## 14.2 Scheduled Plan

| Time    | Script                               | Frequency      | Purpose                       |
| ------- | ------------------------------------ | -------------- | ----------------------------- |
| 7:45 PM | `start_docker_desktop.bat`           | Daily          | Starts Docker Desktop and n8n |
| 8:00 PM | `start_ubuntu_server_vm.bat`         | Daily          | Starts Ubuntu SIEM VM         |
| 8:10 PM | `training_pipeline_every_3_days.bat` | Every 3 days   | Retrains the ML model         |
| 8:40 PM | `daily_detection_pipeline.bat`       | Daily          | Runs detection and alerting   |
| 9:00 PM | `backup_ueba_project.bat`           | Daily          | Backs up outputs              |
| 9:15 PM | `shutdown_ubuntu_server_vm.bat`      | Daily          | Safely shuts down Ubuntu VM   |
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

For Docker Desktop and VMware startup tasks, the workflow uses:

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
examples/     Small sanitized sample outputs
scripts/      Windows automation and validation scripts
src/          Source code for data collection, preprocessing, training, detection, and ingestion
```

## 15.2 Reproducibility Approach

The repository provides the architecture, code structure, configuration templates, documentation, and sample outputs needed to understand and rebuild the system.

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

The lab version may use relaxed certificate verification for local Elasticsearch testing. In a production deployment, certificate verification should be enabled and the Elasticsearch CA certificate should be configured properly.

---

# 17. Evaluation Summary

The project was evaluated through:

| Evaluation method            | Purpose                                                  |
| ---------------------------- | -------------------------------------------------------- |
| Manual anomaly review        | Check whether detected rows make security sense          |
| Model agreement              | Check whether both models flag the same behavior         |
| Model comparison             | Compare IF, LOF, and removed One-Class SVM               |
| Controlled replay validation | Verify detection of generated abnormal behavior          |
| SOC enrichment review        | Confirm that alerts contain useful investigation context |

This is not a full ground-truth accuracy evaluation. True precision, recall, and F1-score require a larger labeled dataset.

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
4. 14-day or longer training windows.
5. Drift monitoring and anomaly-rate trend charts.
6. SOC feedback loop using review statuses.
7. More controlled simulations, including parent-child process anomalies.
8. Labeled evaluation for precision, recall, and F1-score.
9. Optional formal explainability methods.
10. More robust production deployment with verified certificates and hardened secrets management.

---

# 20. Conclusion

The final system is an end-to-end Windows Event/Sysmon UEBA anomaly detection pipeline built using Elasticsearch, Python feature engineering, unsupervised machine learning, anomaly indexing, n8n alerting, and scheduled automation.

The project converts raw endpoint telemetry into behavioral windows, trains an unsupervised Isolation Forest + Local Outlier Factor ensemble, scores new behavior, enriches final anomalies with SOC investigation context, stores alert records in Elasticsearch, and sends SOC-style alerts through n8n.

The final version goes beyond basic anomaly scoring by adding a dataset-builder layer, raw-log investigation metadata, priority scoring, top feature explanations, MITRE ATT&CK-aligned investigation context, Elasticsearch alert indexing, n8n evidence-pack alerting, controlled replay validation, and scheduled operational automation.

This makes the project a reproducible local-lab prototype for automated Windows endpoint UEBA anomaly detection and SOC-oriented alerting.
