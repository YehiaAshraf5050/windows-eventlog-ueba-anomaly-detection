import os
import joblib
import pandas as pd
from datetime import datetime

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

from model_utils import (
    IDENTITY_COLS,
    FEATURE_COLS,
    parse_window_start,
    clean_feature_matrix
)


# ==============================================================================
# CONFIGURATION
# ==============================================================================

TRAINING_WINDOW_DAYS = 7

CONTAMINATION = 0.08

IF_N_ESTIMATORS = 200
IF_RANDOM_STATE = 42

LOF_N_NEIGHBORS = 20

MIN_TRAINING_ROWS = 10

BASE_DIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.dirname(BASE_DIR)

DATASET_PATH = os.path.join(PROJECT_DIR, "preprocessing", "behavior_dataset.csv")
RESULTS_PATH = os.path.join(BASE_DIR, "model_results.csv")


MODEL_REGISTRY_DIR = os.path.join(BASE_DIR, "model_registry")

os.makedirs(MODEL_REGISTRY_DIR, exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

ARTIFACT_PATH_LATEST = os.path.join(
    MODEL_REGISTRY_DIR,
    "model_artifacts_latest.joblib"
)

ARTIFACT_PATH_VERSIONED = os.path.join(
    MODEL_REGISTRY_DIR,
    f"model_artifacts_{timestamp}.joblib"
)
# ==============================================================================
# START
# ==============================================================================

print("=" * 60)
print("PHASE 4: TRAINING")
print("=" * 60)


# ==============================================================================
# STEP 1: LOAD behavior_dataset.csv
# ==============================================================================

if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(
        "behavior_dataset.csv was not found. "
        "Run feature_engineering.py first."
    )


df = pd.read_csv(DATASET_PATH)

df = parse_window_start(df)

print(f"\n[INFO] Total rows loaded: {len(df)}")
print(f"[INFO] Dataset time range: {df['window_start'].min()} -> {df['window_start'].max()}")


# ==============================================================================
# STEP 2: USE RECENT TRAINING WINDOW
# ==============================================================================

# Important:
# We use the latest timestamp inside the dataset, not the computer clock.
#
# Why?
# If your dataset stops at 2026-05-11 and you run the script later,
# using the computer's current date may accidentally remove all rows.
latest_time = df["window_start"].max()

cutoff_time = latest_time - pd.Timedelta(days=TRAINING_WINDOW_DAYS)

recent_df = df[
    df["window_start"] >= cutoff_time
].copy()

print(f"\n[INFO] Training window: last {TRAINING_WINDOW_DAYS} days inside dataset")
print(f"[INFO] Cutoff time: {cutoff_time}")
print(f"[INFO] Latest dataset time: {latest_time}")
print(f"[INFO] Rows inside training window: {len(recent_df)}")


# ==============================================================================
# STEP 3: EXCLUDE PREVIOUS ANOMALIES
# ==============================================================================

rows_excluded = 0

if os.path.exists(RESULTS_PATH):

    print(f"\n[INFO] Found previous model_results.csv")

    previous_results = pd.read_csv(RESULTS_PATH)

    previous_results = parse_window_start(previous_results)

    # Check that model_results.csv has final_anomaly.
    if "final_anomaly" in previous_results.columns:

        known_anomalies = previous_results[
            previous_results["final_anomaly"] == 1
        ][IDENTITY_COLS].copy()

        rows_before = len(recent_df)

        # indicator=True creates a column named _merge.
        # _merge tells us whether the row matched a known anomaly.
        recent_df = recent_df.merge(
            known_anomalies,
            on=IDENTITY_COLS,
            how="left",
            indicator=True
        )

        # After merging recent_df with known_anomalies, pandas creates a helper column
        # called _merge because we used indicator=True.
        #
        # This _merge column tells us whether each row from recent_df matched a row in
        # known_anomalies or not.
        #
        # If _merge == "both", this means the row exists in recent_df and also exists in
        # known_anomalies, so it was previously detected as an anomaly.
        #
        # If _merge == "left_only", this means the row exists only in recent_df and did
        # not match any previous anomaly.
        #
        # We only keep the "left_only" rows because these are the recent behavior rows
        # that were not previously marked as anomalous.
        #
        # This prevents the model from retraining on suspicious behavior and learning it
        # as if it were normal behavior.
        recent_df = recent_df[
            recent_df["_merge"] == "left_only"
        ].drop(columns=["_merge"])

        # rows_before stores how many rows we had before removing previous anomalies.
        # len(recent_df) is the number of rows left after removing them.
        # The difference tells us how many rows were excluded from training.
        rows_excluded = rows_before - len(recent_df)

    else:
        print("[WARNING] model_results.csv exists but has no final_anomaly column")
        print("[WARNING] No anomaly exclusion was applied")

else:
    print("\n[INFO] No previous model_results.csv found")
    print("[INFO] First training run will use all recent rows")

print(f"\n[INFO] Rows excluded as previous anomalies: {rows_excluded}")
print(f"[INFO] Final rows used for training: {len(recent_df)}")


# ==============================================================================
# STEP 4: SAFETY CHECK
# ==============================================================================

if len(recent_df) < MIN_TRAINING_ROWS:
    raise ValueError(
        f"Not enough rows for training. "
        f"Need at least {MIN_TRAINING_ROWS}, found {len(recent_df)}."
    )


# ==============================================================================
# STEP 5: PREPARE FEATURE MATRIX
# ==============================================================================

# X_train is the numeric table used by the models.
# It does not contain user_name, host_name, or window_start.
X_train = clean_feature_matrix(recent_df, FEATURE_COLS)

print(f"\n[INFO] Feature matrix shape: {X_train.shape}")
print("[INFO] Features used for training:")
for feature in FEATURE_COLS:
    print(f" - {feature}")

print("\n[INFO] Identity columns NOT used for training:")
for col in IDENTITY_COLS:
    print(f" - {col}")


# ==============================================================================
# STEP 6: STANDARD SCALER
# ==============================================================================

# StandardScaler performs z-score standardization:
#
# z = (value - mean) / standard deviation
#
# It is used because features have very different scales.
# Example:
# weekend_activity is 0 or 1
# credential_access_volume may be hundreds or thousands
#
# Scaling prevents large-number columns from dominating the models.
scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)

print("\n[INFO] Features scaled with StandardScaler")


# ==============================================================================
# STEP 7: TRAIN ISOLATION FOREST
# ==============================================================================

# Isolation Forest is related to the random forest idea you studied.
# It builds many random trees.
# Anomalies are easier to isolate because they are rare and different.
iso_forest = IsolationForest(n_estimators=IF_N_ESTIMATORS, contamination=CONTAMINATION, random_state=IF_RANDOM_STATE) # Create a model object called iso_forest with the specified parameters.

iso_forest.fit(X_train_scaled) # Train the Isolation Forest model object using the scaled training data.

print("[INFO] Isolation Forest trained")


# ==============================================================================
# STEP 8: TRAIN LOF
# ==============================================================================
# novelty=True is important:
# It allows us to train on historical behavior and then score new unseen windows.
lof_n_neighbors = min(LOF_N_NEIGHBORS, len(X_train) - 1)

if lof_n_neighbors < 2:
    raise ValueError("Not enough rows to train LOF")

lof = LocalOutlierFactor(n_neighbors=lof_n_neighbors, contamination=CONTAMINATION, novelty=True)

lof.fit(X_train_scaled)

print(f"[INFO] LOF trained with n_neighbors={lof_n_neighbors}")


# STEP 10: CALCULATE TRAINING SCORE RANGES
# ==============================================================================

# We calculate anomaly scores on the training data itself.
#
# Why?
# Later, detect_anomaly.py may score only one latest row.
# If we tried to scale that one row using its own min and max, the score would
# have no meaning. So we save the min and max anomaly scores seen during training.
#
# Then during detection, the new row's scores are compared to these saved
# training score ranges.

if_train_score = -iso_forest.decision_function(X_train_scaled)
lof_train_score = -lof.decision_function(X_train_scaled)

score_ranges = {
    "if_score_min": if_train_score.min(),
    "if_score_max": if_train_score.max(),

    "lof_score_min": lof_train_score.min(),
    "lof_score_max": lof_train_score.max(),

}

print("\n[INFO] Training score ranges:")
print(f"[INFO] IF score range : {score_ranges['if_score_min']} -> {score_ranges['if_score_max']}")
print(f"[INFO] LOF score range: {score_ranges['lof_score_min']} -> {score_ranges['lof_score_max']}")



# ==============================================================================
# STEP 11: SAVE ARTIFACTS
# ==============================================================================

# joblib saves trained Python objects to a file.
# detect_anomaly.py will load this file instead of retraining from scratch.
artifacts = {
    "scaler": scaler,

    "iso_forest": iso_forest,

    "lof": lof,
    
    "feature_cols": FEATURE_COLS,
    "identity_cols": IDENTITY_COLS,
    "score_ranges": score_ranges,
    "training_metadata": {
        "training_window_days": TRAINING_WINDOW_DAYS,
        "cutoff_time": str(cutoff_time),
        "latest_training_time": str(latest_time),
        "training_rows": len(X_train),
        "rows_excluded_as_previous_anomalies": rows_excluded,
        "contamination": CONTAMINATION,
        "lof_n_neighbors": lof_n_neighbors,
    }
}

joblib.dump(
    artifacts,
    ARTIFACT_PATH_LATEST
)

joblib.dump(
    artifacts,
    ARTIFACT_PATH_VERSIONED
)

print(f"\n[INFO] Saved latest model artifact to: {ARTIFACT_PATH_LATEST}")
print(f"[INFO] Saved versioned model artifact to: {ARTIFACT_PATH_VERSIONED}")

# ==============================================================================
# SUMMARY
# ==============================================================================

print("\n" + "=" * 60)
print("TRAINING COMPLETE")
print("=" * 60)
print(f"Dataset rows loaded: {len(df)}")
print(f"Training window: last {TRAINING_WINDOW_DAYS} days")
print(f"Rows used for training: {len(X_train)}")
print(f"Rows excluded as anomalies: {rows_excluded}")
print("Models trained: Isolation Forest, LOF")
print("Next step: run detect_anomaly.py")
print("=" * 60)