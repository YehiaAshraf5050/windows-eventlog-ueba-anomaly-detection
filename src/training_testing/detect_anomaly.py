import os
import joblib
import pandas as pd

from model_utils import (
    IDENTITY_COLS,
    parse_window_start,
    score_rows,
    upsert_results
)


# ==============================================================================
# CONFIGURATION
# ==============================================================================

BASE_DIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.dirname(BASE_DIR)

DATASET_PATH = os.path.join(PROJECT_DIR, "preprocessing", "behavior_dataset.csv")
RESULTS_PATH = os.path.join(BASE_DIR, "model_results.csv")
ARTIFACT_PATH = os.path.join(BASE_DIR, "model_registry", "model_artifacts_latest.joblib")
# "latest" means score only the latest available 10-minute window.
# "all" means score the whole behavior_dataset.csv.
# "new" means score only rows that are not already in model_results.csv.
#
# Use "all" the first time if you want model_results.csv for all old rows.
# Then switch it back to "new" for operational use.
SCORING_MODE = "new"
# ==============================================================================
# ENRICHMENT CONFIGURATION
# ==============================================================================

RAW_INDEX_NAME = "winlogbeat-whatever"
WINDOW_SIZE_MINUTES = 10

# These rules do not replace the ML model.
# They add SOC-oriented priority scoring after the model has already scored the row.
RISK_RULES = {
    "failed_login_count": {
        "threshold": 5,
        "points": 2,
        "reason": "failed login burst"
    },
    "credential_access_count": {
        "threshold": 50,
        "points": 3,
        "reason": "credential access spike"
    },
    "credential_access_volume": {
        "threshold": 100,
        "points": 2,
        "reason": "high credential access volume"
    },
    "powershell_exec_count": {
        "threshold": 10,
        "points": 2,
        "reason": "PowerShell execution spike"
    },
    "cmd_exec_count": {
        "threshold": 10,
        "points": 2,
        "reason": "CMD execution spike"
    },
    "shell_ratio": {
        "threshold": 0.5,
        "points": 2,
        "reason": "shell-heavy process activity"
    },
    "suspicious_parent_count": {
        "threshold": 1,
        "points": 2,
        "reason": "suspicious parent process activity"
    },
    "network_connection_count": {
        "threshold": 50,
        "points": 1,
        "reason": "network activity spike"
    },
    "file_creation_count": {
        "threshold": 100,
        "points": 1,
        "reason": "file creation burst"
    },
    "suspicious_file_creation_count": {
        "threshold": 10,
        "points": 2,
        "reason": "suspicious file creation spike"
    },
    "weekend_activity": {
        "threshold": 1,
        "points": 1,
        "reason": "weekend activity"
    }
}

# These features are used to produce a practical SOC explanation.
# This is not SHAP/LIME model attribution.
# It simply reports the strongest non-zero security-relevant values in the anomalous window.
EXPLAIN_FEATURES = [
    "credential_access_count",
    "credential_access_volume",
    "process_creation_count",
    "powershell_exec_count",
    "cmd_exec_count",
    "shell_ratio",
    "suspicious_parent_count",
    "network_connection_count",
    "file_creation_count",
    "suspicious_file_creation_count",
    "failed_login_count",
    "failed_success_ratio"
]

# MITRE ATT&CK-aligned indicators.
# These are investigation hints, not confirmed attack attribution.
MITRE_RULES = {
    "powershell_exec_count": {
        "threshold": 1,
        "indicator": "Command and Scripting Interpreter",
        "technique": "T1059",
        "note": "PowerShell execution was observed in the anomalous window"
    },
    "cmd_exec_count": {
        "threshold": 1,
        "indicator": "Command and Scripting Interpreter",
        "technique": "T1059",
        "note": "CMD execution was observed in the anomalous window"
    },
    "failed_login_count": {
        "threshold": 5,
        "indicator": "Brute Force / Valid Accounts indicator",
        "technique": "T1110 / T1078",
        "note": "Multiple failed login attempts were observed"
    },
    "credential_access_count": {
        "threshold": 10,
        "indicator": "Credential Access indicator",
        "technique": "Credential Access tactic",
        "note": "Credential-related activity was elevated"
    },
    "suspicious_file_creation_count": {
        "threshold": 5,
        "indicator": "Suspicious file staging indicator",
        "technique": "File and Directory Discovery / tool staging context",
        "note": "Suspicious script or executable file creation was observed"
    },
    "suspicious_parent_count": {
        "threshold": 1,
        "indicator": "Suspicious process chain indicator",
        "technique": "Defense Evasion context",
        "note": "Suspicious parent-child process behavior was observed"
    },
    "network_connection_count": {
        "threshold": 50,
        "indicator": "Unusual network communication indicator",
        "technique": "Command and Control / Exfiltration context",
        "note": "Network activity was elevated in the window"
    }
}

# ==============================================================================
# START
# ==============================================================================

print("=" * 60)
print("PHASE 4: DETECTION")
print("=" * 60)


# ==============================================================================
# STEP 1: LOAD DATASET
# ==============================================================================

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(
        "behavior_dataset.csv was not found. "
        "Run feature_engineering.py first."
    )

df = pd.read_csv(DATASET_PATH)

df = parse_window_start(df)

print(f"\n[INFO] Total behavior rows loaded: {len(df)}")
print(f"[INFO] Dataset time range: {df['window_start'].min()} -> {df['window_start'].max()}")


# ==============================================================================
# STEP 2: LOAD SAVED MODEL
# ==============================================================================

if not os.path.exists(ARTIFACT_PATH):
    raise FileNotFoundError(
        "model_artifacts.joblib was not found. "
        "Run train_model.py first."
    )

artifacts = joblib.load(ARTIFACT_PATH)

scaler = artifacts["scaler"]

iso_forest = artifacts["iso_forest"]
lof = artifacts["lof"]

feature_cols = artifacts["feature_cols"]
score_ranges = artifacts["score_ranges"]
training_metadata = artifacts["training_metadata"]

print("\n[INFO] Loaded model_artifacts.joblib")
print("[INFO] Model training metadata:")
for key, value in training_metadata.items():
    print(f" - {key}: {value}")


# ==============================================================================
# STEP 3: SELECT ROWS TO SCORE
# ==============================================================================

if SCORING_MODE == "latest":

    latest_time = df["window_start"].max()

    scoring_df = df[df["window_start"] == latest_time].copy()

    print("\n[INFO] Scoring mode: latest")
    print(f"[INFO] Latest window_start: {latest_time}")
    print(f"[INFO] Rows to score: {len(scoring_df)}")

elif SCORING_MODE == "all":

    scoring_df = df.copy()

    print("\n[INFO] Scoring mode: all")
    print(f"[INFO] Rows to score: {len(scoring_df)}")

elif SCORING_MODE == "new":

    if os.path.exists(RESULTS_PATH):

        old_results = pd.read_csv(RESULTS_PATH)
        old_results = parse_window_start(old_results)

        already_scored = old_results[IDENTITY_COLS].copy()

        scoring_df = df.merge(
            already_scored,
            on=IDENTITY_COLS,
            how="left",
            indicator=True
        )

        scoring_df = scoring_df[
            scoring_df["_merge"] == "left_only"
        ].drop(columns=["_merge"]).copy()

    else:
        scoring_df = df.copy()

    print("\n[INFO] Scoring mode: new")
    print(f"[INFO] New rows to score: {len(scoring_df)}")

else:
    raise ValueError("SCORING_MODE must be either 'latest', 'all', or 'new'")


# This IF block decides which rows from behavior_dataset.csv will be scored
# by the anomaly detection models in this run.
#
# If SCORING_MODE == "latest", the script finds the maximum window_start value
# in the dataset. This represents the newest 10-minute time window available.
# Then it keeps only the rows that belong to that exact latest window. This mode
# is useful if we only want to check the most recent time window.
#
# If SCORING_MODE == "all", the script copies the entire dataset and scores every
# row in behavior_dataset.csv. This is useful for the first detection run because
# model_results.csv does not exist yet, so we want to score all historical windows
# and create the initial results file.
#
# If SCORING_MODE == "new", the script compares behavior_dataset.csv with the
# already saved model_results.csv. It keeps only the rows that exist in the dataset
# but do not already exist in model_results.csv. This is the best mode for real-time
# use because if feature_engineering.py adds 20 new behavior rows, detection will
# score those 20 new rows instead of rescoring the whole dataset or only the latest
# timestamp.
#
# If SCORING_MODE has any value other than "latest", "all", or "new", the script
# stops with an error. This prevents running the detection script with an invalid
# scoring mode.

# ==============================================================================
# ENRICHMENT HELPER FUNCTIONS
# ==============================================================================

def get_model_priority(row):
    """
    Give priority points based on model agreement and ensemble score.
    This is added after anomaly detection to help SOC triage.
    """

    points = 0
    reasons = []

    if row.get("if_anomaly", 0) == 1 and row.get("lof_anomaly", 0) == 1:
        points += 3
        reasons.append("Isolation Forest and LOF both flagged the window")

    elif row.get("ensemble_votes", 0) >= 1:
        points += 1
        reasons.append("one model flagged the window")

    ensemble_score = row.get("ensemble_score", 0)

    if ensemble_score >= 0.85:
        points += 2
        reasons.append("high ensemble score")

    elif ensemble_score >= 0.65:
        points += 1
        reasons.append("medium ensemble score")

    return points, reasons


def get_feature_priority(row):
    """
    Give priority points based on high-risk feature triggers.
    These thresholds are SOC triage rules, not ML training rules.
    """

    points = 0
    reasons = []

    for feature, rule in RISK_RULES.items():

        value = row.get(feature, 0)

        if value >= rule["threshold"]:

            points += rule["points"]

            reasons.append(
                f"{rule['reason']} ({feature}={value})"
            )

    return points, reasons

def has_strong_security_evidence(row):
    """
    Decide whether a behavior window contains strong security evidence.

    These rules are used to prevent weak single-model statistical deviations
    from becoming final SOC anomalies unless they contain security-relevant
    behavior.
    """

    return (
        row.get("failed_login_count", 0) >= 10
        or row.get("suspicious_file_creation_count", 0) >= 20
        or (
            row.get("powershell_exec_count", 0) >= 50
            and row.get("cmd_exec_count", 0) >= 50
        )
        or (
            row.get("shell_ratio", 0) >= 0.50
            and row.get("process_creation_count", 0) >= 50
        )
        or row.get("suspicious_parent_count", 0) >= 3
    )


def calculate_preliminary_priority(row):
    """
    Calculate priority score before the final anomaly decision.

    This is needed because the stricter final decision uses priority-like
    security context to avoid promoting weak model-only outliers.
    """

    model_points, _ = get_model_priority(row)
    feature_points, _ = get_feature_priority(row)

    return model_points + feature_points


def apply_strict_final_decision(results_df):
    """
    Replace the loose final_anomaly decision with a stricter SOC-oriented rule.

    Final anomaly becomes 1 only if:
    1. IF and LOF both agree and the row has enough priority/security context.
    OR
    2. At least one model flags the row and strong security evidence exists.

    This keeps controlled security-relevant behavior detectable while reducing
    weak single-model anomaly promotion.
    """

    results_df = results_df.copy()

    final_decisions = []
    detection_reasons = []
    severities = []

    for _, row in results_df.iterrows():

        model_agreement = row.get("ensemble_votes", 0) >= 2
        one_model_flagged = row.get("ensemble_votes", 0) >= 1

        strong_security_evidence = has_strong_security_evidence(row)
        preliminary_priority = calculate_preliminary_priority(row)

        high_priority_model_agreement = (
            model_agreement
            and preliminary_priority >= 6
        )

        model_supported_security_evidence = (
            one_model_flagged
            and strong_security_evidence
        )

        if high_priority_model_agreement:
            final_decisions.append(1)
            detection_reasons.append("model_vote_high_priority")
            severities.append("high")

        elif model_supported_security_evidence:
            final_decisions.append(1)
            detection_reasons.append("security_rule_model_supported")

            if preliminary_priority >= 9:
                severities.append("high")
            elif preliminary_priority >= 6:
                severities.append("medium")
            else:
                severities.append("low")

        else:
            final_decisions.append(0)
            detection_reasons.append("normal")
            severities.append("normal")

    results_df["final_anomaly"] = final_decisions
    results_df["detection_reason"] = detection_reasons
    results_df["severity"] = severities

    return results_df

def get_priority_level(score):
    """
    Convert numeric priority score into a SOC-readable level.
    """

    if score >= 9:
        return "critical"

    elif score >= 6:
        return "high"

    elif score >= 3:
        return "medium"

    return "low"


def get_top_features(row, n=5):
    """
    Return the top non-zero security-relevant feature values.

    This is practical explainability for SOC review.
    It is not formal model attribution.
    """

    feature_values = []

    for feature in EXPLAIN_FEATURES:

        value = row.get(feature, 0)

        if value > 0:

            feature_values.append(
                {
                    "feature": feature,
                    "value": float(value)
                }
            )

    feature_values = sorted(
        feature_values,
        key=lambda item: item["value"],
        reverse=True
    )

    return feature_values[:n]


def get_mitre_indicators(row):
    """
    Map abnormal feature triggers to MITRE ATT&CK-aligned indicators.

    Important:
    These are investigation indicators only.
    They do not prove that a specific MITRE technique occurred.
    """

    indicators = []

    for feature, rule in MITRE_RULES.items():

        value = row.get(feature, 0)

        if value >= rule["threshold"]:

            indicators.append(
                {
                    "feature": feature,
                    "value": float(value),
                    "indicator": rule["indicator"],
                    "technique": rule["technique"],
                    "note": rule["note"]
                }
            )

    return indicators


def build_investigation_query(row):
    """
    Build a simple Elasticsearch/Kibana investigation query.

    The analyst can use this query to search the original raw logs
    for the same user, host, and 10-minute anomaly window.
    """

    window_start = pd.to_datetime(
        row["window_start"],
        utc=True,
        errors="coerce"
    )

    if pd.isna(window_start):
        return ""

    window_end = window_start + pd.Timedelta(minutes=WINDOW_SIZE_MINUTES)

    user_name = str(row.get("user_name", ""))
    host_name = str(row.get("host_name", ""))

    return (
        f'user_name:"{user_name}" AND '
        f'host_name:"{host_name}" AND '
        f'@timestamp:["{window_start.isoformat()}" TO "{window_end.isoformat()}"]'
    )


def enrich_detection_results(results_df):
    """
    Add SOC-oriented enrichment fields to model results.

    Added fields:
    - window_end
    - raw_index
    - investigation_query
    - priority_score
    - priority_level
    - priority_reason
    - top_features
    - mitre_aligned_indicators
    """

    results_df = results_df.copy()

    results_df["window_start"] = pd.to_datetime(
        results_df["window_start"],
        utc=True,
        errors="coerce"
    )

    results_df["window_end"] = (
        results_df["window_start"] + pd.Timedelta(minutes=WINDOW_SIZE_MINUTES)
    )

    results_df["raw_index"] = RAW_INDEX_NAME

    priority_scores = []
    priority_levels = []
    priority_reasons = []
    top_features_list = []
    investigation_queries = []
    mitre_indicators_list = []

    for _, row in results_df.iterrows():

        # Only enrich final anomalies with SOC priority, top features, MITRE indicators,
        # and raw-log investigation query.
        # Normal rows do not receive alert priority or investigation query.
        if row.get("final_anomaly", 0) != 1:

            priority_scores.append(0)
            priority_levels.append("normal")
            priority_reasons.append("")
            top_features_list.append("[]")
            investigation_queries.append("")
            mitre_indicators_list.append("[]")

            continue

        model_points, model_reasons = get_model_priority(row)
        feature_points, feature_reasons = get_feature_priority(row)

        total_score = model_points + feature_points

        priority_scores.append(total_score)
        priority_levels.append(get_priority_level(total_score))
        priority_reasons.append("; ".join(model_reasons + feature_reasons))

        top_features_list.append(str(get_top_features(row)))
        investigation_queries.append(build_investigation_query(row))
        mitre_indicators_list.append(str(get_mitre_indicators(row)))

    results_df["priority_score"] = priority_scores
    results_df["priority_level"] = priority_levels
    results_df["priority_reason"] = priority_reasons
    results_df["top_features"] = top_features_list
    results_df["investigation_query"] = investigation_queries
    results_df["mitre_aligned_indicators"] = mitre_indicators_list

    return results_df
# ==============================================================================
# STEP 4: SCORE ROWS
# ==============================================================================

new_results = score_rows(
    rows_df=scoring_df,
    scaler=scaler,
    iso_forest=iso_forest,
    lof=lof,
    feature_cols=feature_cols,
    score_ranges=score_ranges
)

# Apply stricter SOC-oriented final decision after ML scoring.
new_results = apply_strict_final_decision(new_results)

# Add SOC-oriented enrichment fields after the final anomaly decision.
new_results = enrich_detection_results(new_results)

# Sort so the most suspicious rows appear first in the terminal.
new_results = new_results.sort_values(
    by=[
        "final_anomaly",
        "priority_score",
        "ensemble_votes",
        "ensemble_score"
    ],
    ascending=[
        False,
        False,
        False,
        False
    ]
).reset_index(drop=True)


# ==============================================================================
# STEP 5: SAVE OR UPDATE model_results.csv
# ==============================================================================

if os.path.exists(RESULTS_PATH):

    old_results = pd.read_csv(RESULTS_PATH)
    old_results = parse_window_start(old_results)

    combined_results = upsert_results(
        old_results,
        new_results
    )

else:
    combined_results = new_results.copy()

combined_results.to_csv(RESULTS_PATH, index=False)

print(f"\n[INFO] Results saved to: {RESULTS_PATH}")


# ==============================================================================
# SUMMARY
# ==============================================================================

# new_results is the table returned from score_rows().
# It contains only the rows that were scored in the current detection run.
#
# Inside new_results, the final_anomaly column contains the final decision:
# 0 means the row is normal.
# 1 means the row is anomalous.
#
# Because anomalies are represented as 1, summing the final_anomaly column gives
# the total number of anomalous rows detected in this run.
#
# Example:
# final_anomaly values: 0, 1, 0, 1, 1
# sum = 3
# This means 3 rows were detected as anomalies.
#
# int() converts the result into a normal Python integer so it can be printed
# cleanly in the summary.
anomaly_count = int(new_results["final_anomaly"].sum())

print("\n" + "=" * 60)
print("DETECTION COMPLETE")
print("=" * 60)
print(f"Rows scored this run: {len(new_results)}")
print(f"Final anomalies detected this run: {anomaly_count}")
print("=" * 60)


# ==============================================================================
# DISPLAY TOP SUSPICIOUS WINDOWS
# ==============================================================================

columns_to_show = [
    "user_name",
    "host_name",
    "window_start",
    "window_end",

    "final_anomaly",
    "detection_reason",
    "severity",

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
    if col in new_results.columns
]

print("\n[INFO] Top suspicious windows:")
print(
    new_results[available_columns]
    .head(15)
    .to_string(index=False)
)