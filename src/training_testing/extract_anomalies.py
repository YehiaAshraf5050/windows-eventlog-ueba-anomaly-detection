import os
import pandas as pd

from model_utils import (
    IDENTITY_COLS,
    parse_window_start
)


# ==============================================================================
# CONFIGURATION
# ==============================================================================

BASE_DIR = os.path.dirname(__file__)

RESULTS_PATH = os.path.join(BASE_DIR, "model_results.csv")
ANOMALIES_PATH = os.path.join(BASE_DIR, "anomalies.csv")


# ==============================================================================
# START
# ==============================================================================

print("=" * 60)
print("EXTRACT ANOMALIES")
print("=" * 60)


# ==============================================================================
# STEP 1: LOAD model_results.csv
# ==============================================================================

if not os.path.exists(RESULTS_PATH):
    raise FileNotFoundError(
        "model_results.csv was not found. "
        "Run detect_anomaly.py first."
    )

results_df = pd.read_csv(RESULTS_PATH)
results_df = parse_window_start(results_df)

print(f"\n[INFO] Total rows loaded from model_results.csv: {len(results_df)}")


# ==============================================================================
# STEP 2: KEEP ONLY FINAL ANOMALIES
# ==============================================================================

if "final_anomaly" not in results_df.columns:
    raise ValueError("model_results.csv does not contain final_anomaly column.")

new_anomalies = results_df[
    results_df["final_anomaly"] == 1
].copy()

print(f"[INFO] Anomaly rows found in model_results.csv: {len(new_anomalies)}")


# ==============================================================================
# STEP 3: UPDATE anomalies.csv WITHOUT DUPLICATES
# ==============================================================================

if os.path.exists(ANOMALIES_PATH):

    old_anomalies = pd.read_csv(ANOMALIES_PATH)
    old_anomalies = parse_window_start(old_anomalies)

    combined_anomalies = pd.concat(
        [old_anomalies, new_anomalies],
        ignore_index=True
    )

else:
    combined_anomalies = new_anomalies.copy()


combined_anomalies = parse_window_start(combined_anomalies)

combined_anomalies = combined_anomalies.drop_duplicates(
    subset=IDENTITY_COLS,
    keep="last"
)

combined_anomalies = combined_anomalies.sort_values(
    by=[
        "window_start",
        "severity",
        "ensemble_score"
    ],
    ascending=[
        False,
        True,
        False
    ]
).reset_index(drop=True)


# ==============================================================================
# STEP 4: SAVE anomalies.csv
# ==============================================================================

combined_anomalies.to_csv(
    ANOMALIES_PATH,
    index=False
)

print(f"\n[INFO] anomalies.csv saved to: {ANOMALIES_PATH}")
print(f"[INFO] Total unique anomalies saved: {len(combined_anomalies)}")


# ==============================================================================
# SUMMARY
# ==============================================================================

print("\n" + "=" * 60)
print("ANOMALY EXTRACTION COMPLETE")
print("=" * 60)
print(f"New anomaly rows found: {len(new_anomalies)}")
print(f"Total unique anomalies saved: {len(combined_anomalies)}")
print("=" * 60)


# ==============================================================================
# DISPLAY TOP ANOMALIES
# ==============================================================================

columns_to_show = [
    "user_name",
    "host_name",
    "window_start",
    "window_end",

    "severity",
    "detection_reason",

    "priority_score",
    "priority_level",

    "ensemble_votes",
    "ensemble_score",

    "if_anomaly",
    "lof_anomaly",

    "successful_login_count",
    "failed_login_count",
    "credential_access_volume",
    "process_creation_count",
    "powershell_exec_count",
    "cmd_exec_count",
    "network_connection_count",
    "file_creation_count",
    "suspicious_file_creation_count",
    "activity_hour",
    "weekend_activity",
]

available_columns = [
    col for col in columns_to_show
    if col in combined_anomalies.columns
]

print("\n[INFO] Latest extracted anomalies:")
print(
    combined_anomalies[available_columns]
    .head(15)
    .to_string(index=False)
)