import os
import sys
import hashlib
from datetime import datetime, timezone

import pandas as pd
import requests
from elasticsearch import Elasticsearch


# ==============================================================================
# PATH SETUP
# ==============================================================================

BASE_DIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.dirname(BASE_DIR)

# Add project root so we can import config.py
sys.path.append(PROJECT_DIR)

from config import (
    ELASTIC_HOST,
    ELASTIC_USER,
    ELASTIC_PASSWORD,
    N8N_WEBHOOK_PRODUCTION_URL
)


# ==============================================================================
# CONFIGURATION
# ==============================================================================

ANOMALIES_PATH = os.path.join(
    PROJECT_DIR,
    "training_testing",
    "anomalies.csv"
)

ANOMALY_INDEX_NAME = "ueba-anomalies"
N8N_URL = N8N_WEBHOOK_PRODUCTION_URL


# ==============================================================================
# ELASTICSEARCH CONNECTION
# ==============================================================================

es = Elasticsearch(
    ELASTIC_HOST,
    basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
    verify_certs=False
)


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def create_anomaly_id(row):
    """
    Create a unique ID for each anomaly document.

    We use:
    user_name + host_name + window_start

    This makes each anomaly unique because each row represents one user,
    one host, and one 10-minute behavior window.

    If this script runs multiple times, the same anomaly will generate the same
    document ID. This prevents duplicate documents in Elasticsearch.
    """

    unique_text = (
        str(row["user_name"])
        + "_"
        + str(row["host_name"])
        + "_"
        + str(row["window_start"])
    )

    return hashlib.sha256(
        unique_text.encode("utf-8")
    ).hexdigest()


def safe_value(value):
    """
    Convert pandas missing values into None.

    Elasticsearch and n8n receive JSON data.
    JSON does not handle pandas NaN values cleanly, so we convert missing values
    into None.
    """

    if pd.isna(value):
        return None

    return value


def row_to_document(row):
    """
    Convert one anomaly row from anomalies.csv into a JSON-friendly Python
    dictionary.

    This dictionary will be:
    1. Stored in Elasticsearch
    2. Sent to n8n webhook
    """

    window_start = pd.to_datetime(
        row["window_start"],
        utc=True,
        errors="coerce"
    )

    if pd.isna(window_start):
        window_start_iso = None
        window_end_iso = None
    else:
        window_start_iso = window_start.isoformat()
        window_end_iso = (window_start + pd.Timedelta(minutes=10)).isoformat()

    document = {
        "user_name": safe_value(row.get("user_name")),
        "host_name": safe_value(row.get("host_name")),

        "window_start": window_start_iso,
        "window_end": window_end_iso,

        # Raw-log investigation metadata.
        "raw_index": safe_value(row.get("raw_index")),
        "investigation_query": safe_value(row.get("investigation_query")),

        "final_anomaly": int(row.get("final_anomaly", 1)),
        "severity": safe_value(row.get("severity")),
        "detection_reason": safe_value(row.get("detection_reason")),

        # SOC prioritization and explanation.
        "priority_score": float(row.get("priority_score", 0)),
        "priority_level": safe_value(row.get("priority_level")),
        "priority_reason": safe_value(row.get("priority_reason")),
        "top_features": safe_value(row.get("top_features")),
        "mitre_aligned_indicators": safe_value(row.get("mitre_aligned_indicators")),

        "ensemble_votes": int(row.get("ensemble_votes", 0)),
        "ensemble_score": float(row.get("ensemble_score", 0)),

        "if_anomaly": int(row.get("if_anomaly", 0)),
        "lof_anomaly": int(row.get("lof_anomaly", 0)),

        "if_score_scaled": float(row.get("if_score_scaled", 0)),
        "lof_score_scaled": float(row.get("lof_score_scaled", 0)),

        "successful_login_count": float(row.get("successful_login_count", 0)),
        "failed_login_count": float(row.get("failed_login_count", 0)),
        "failed_success_ratio": float(row.get("failed_success_ratio", 0)),

        "credential_access_count": float(row.get("credential_access_count", 0)),
        "credential_access_volume": float(row.get("credential_access_volume", 0)),
        "credential_volume_per_read": float(row.get("credential_volume_per_read", 0)),

        "process_creation_count": float(row.get("process_creation_count", 0)),
        "unique_process_count": float(row.get("unique_process_count", 0)),
        "process_diversity_ratio": float(row.get("process_diversity_ratio", 0)),

        "powershell_exec_count": float(row.get("powershell_exec_count", 0)),
        "cmd_exec_count": float(row.get("cmd_exec_count", 0)),
        "shell_ratio": float(row.get("shell_ratio", 0)),

        "suspicious_parent_count": float(row.get("suspicious_parent_count", 0)),

        "network_connection_count": float(row.get("network_connection_count", 0)),
        "network_per_process": float(row.get("network_per_process", 0)),

        "file_creation_count": float(row.get("file_creation_count", 0)),
        "suspicious_file_creation_count": float(row.get("suspicious_file_creation_count", 0)),
        "file_per_process": float(row.get("file_per_process", 0)),

        "unique_login_types": float(row.get("unique_login_types", 0)),
        "activity_hour": float(row.get("activity_hour", 0)),
        "weekend_activity": float(row.get("weekend_activity", 0)),

        # SOC review fields.
        "review_status": "pending_review",
        "analyst_comment": "",

        # Alerting fields.
        # This starts as not_sent. After the webhook succeeds, we update it to sent.
        "alert_status": "not_sent",

        # Metadata.
        "source_file": "anomalies.csv",
        "created_at": datetime.now(timezone.utc).isoformat()
    }

    return document

# ==============================================================================
# START
# ==============================================================================

print("=" * 60)
print("SEND ANOMALIES TO ELASTICSEARCH AND N8N")
print("=" * 60)


# ==============================================================================
# STEP 1: CHECK ELASTICSEARCH CONNECTION
# ==============================================================================

if not es.ping():
    raise ConnectionError(
        "Could not connect to Elasticsearch. "
        "Check ELASTIC_HOST, username, password, and SSL settings."
    )

print("\n[INFO] Connected to Elasticsearch")


# ==============================================================================
# STEP 2: LOAD anomalies.csv
# ==============================================================================

if not os.path.exists(ANOMALIES_PATH):
    raise FileNotFoundError(
        "anomalies.csv was not found. "
        "Run extract_anomalies.py first."
    )

anomalies_df = pd.read_csv(ANOMALIES_PATH)

print(f"[INFO] Loaded anomaly rows: {len(anomalies_df)}")

if len(anomalies_df) == 0:
    print("[INFO] No anomalies to send.")
    exit()

# ==============================================================================
# STEP 3: SEND ANOMALIES TO ELASTICSEARCH AND N8N
# ==============================================================================

elastic_sent_count = 0
skipped_existing_count = 0
failed_count = 0

new_documents_for_n8n = []

for _, row in anomalies_df.iterrows():

    try:
        document_id = create_anomaly_id(row)
        document = row_to_document(row)

        already_exists = es.exists(
            index=ANOMALY_INDEX_NAME,
            id=document_id
        )

        if already_exists:
            skipped_existing_count += 1
            continue

        es.index(
            index=ANOMALY_INDEX_NAME,
            id=document_id,
            document=document
        )

        elastic_sent_count += 1

        # Keep the document id inside the payload so n8n/SOC can reference it.
        document["elastic_index"] = ANOMALY_INDEX_NAME
        document["elastic_document_id"] = document_id

        new_documents_for_n8n.append(document)

    except Exception as error:
        failed_count += 1
        print("[ERROR] Failed to process anomaly:")
        print(error)


# ==============================================================================
# STEP 4: SEND ONE BATCH TO N8N
# ==============================================================================

n8n_sent_count = 0

if len(new_documents_for_n8n) > 0:

    payload = {
        "alert_type": "ueba_anomaly_batch",
        "total_anomalies": len(new_documents_for_n8n),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "anomalies": new_documents_for_n8n
    }

    try:
        response = requests.post(
            N8N_URL,
            json=payload,
            timeout=10
        )

        response.raise_for_status()

        n8n_sent_count = len(new_documents_for_n8n)

        # After the webhook succeeds, update alert_status for all sent documents.
        for document in new_documents_for_n8n:
            es.update(
                index=ANOMALY_INDEX_NAME,
                id=document["elastic_document_id"],
                doc={
                    "alert_status": "sent",
                    "alert_sent_at": datetime.now(timezone.utc).isoformat()
                }
            )

        print(f"[INFO] Sent one batch to n8n containing {n8n_sent_count} anomalies")

    except Exception as error:
        failed_count += 1
        print("[ERROR] Failed to send anomaly batch to n8n:")
        print(error)

else:
    print("[INFO] No new anomalies to send to n8n.")
# ==============================================================================
# SUMMARY
# ==============================================================================

print("\n" + "=" * 60)
print("ANOMALY EXPORT COMPLETE")
print("=" * 60)
print(f"Index name: {ANOMALY_INDEX_NAME}")
print(f"New anomalies stored in Elasticsearch: {elastic_sent_count}")
print(f"New anomalies sent to n8n: {n8n_sent_count}")
print(f"Existing anomalies skipped to avoid duplicate alerts: {skipped_existing_count}")
print(f"Failed rows: {failed_count}")
print("=" * 60)