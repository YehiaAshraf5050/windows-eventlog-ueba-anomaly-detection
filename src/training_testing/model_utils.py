import numpy as np
import pandas as pd


# These columns explain the row, but they are NOT used for training.
# They tell us who, on which machine, and at what time.
IDENTITY_COLS = [
    "user_name",
    "host_name",
    "window_start"
]


# These are the actual behavioral features used by the ML models.
# Each row is a 10-minute behavior window.
FEATURE_COLS = [
    "successful_login_count",
    "failed_login_count",
    "failed_success_ratio",

    "credential_access_count",
    "credential_access_volume",
    "credential_volume_per_read",

    "process_creation_count",
    "unique_process_count",
    "process_diversity_ratio",

    "powershell_exec_count",
    "cmd_exec_count",
    "shell_ratio",

    "suspicious_parent_count",

    "network_connection_count",
    "network_per_process",

    "file_creation_count",
    "suspicious_file_creation_count",
    "file_per_process",

    "unique_login_types",

    "activity_hour",
    "weekend_activity",
]


def parse_window_start(df):
    """
    Convert window_start from text into a real datetime value.

    Why?
    CSV files store dates as text.
    Pandas needs a real datetime type so we can sort, filter, and compare times.
    """

    df = df.copy()

    df["window_start"] = pd.to_datetime(
        df["window_start"],
        utc=True,
        errors="coerce"
    )

    # Remove rows where the timestamp could not be parsed.
    df = df[df["window_start"].notna()].copy()

    return df


def clean_feature_matrix(df, feature_cols):
    """
    Create the feature matrix X.

    X means the numeric input table given to the ML models.

    We do not include:
    - user_name
    - host_name
    - window_start

    because they are identity/explanation columns, not behavior measurements.
    """

    missing_cols = [
        col for col in feature_cols
        if col not in df.columns
    ]

    if missing_cols:
        raise ValueError(f"Missing feature columns: {missing_cols}")

    X = df[feature_cols].copy()

    # Force all features to become numeric.
    # If pandas cannot convert a value, it becomes NaN.
    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    # Replace infinite values with NaN.
    X = X.replace(
        [np.inf, -np.inf],
        np.nan
    )

    # Fill missing values with 0 so the model does not crash.
    X = X.fillna(0)

    return X


def sklearn_prediction_to_flag(predictions):
    """
    scikit-learn anomaly models usually return:

    1  = normal
    -1 = anomaly

    For our project, we convert this into:

    0 = normal
    1 = anomaly
    """

    return (predictions == -1).astype(int)


def scale_scores_with_training_range(values, saved_min, saved_max):
    """
    Scale anomaly scores from 0 to 1 using the score range saved during training.

    This is used for ensemble_score.

    We do not scale detection scores using their own min and max, because in
    real-time detection we may score only one latest row. If we scaled one row
    against itself, min and max would be the same and the score would have no
    useful meaning.

    Instead, we compare the new row's anomaly score to the range of scores seen
    during training. This makes the score meaningful even when detecting one row.
    """

    values = np.array(values)

    if saved_max == saved_min:
        return np.zeros(len(values))

    scaled_values = (values - saved_min) / (saved_max - saved_min)

    # Keep the score inside the readable range 0 to 1.
    scaled_values = np.clip(
        scaled_values,
        0,
        1
    )

    return scaled_values



def score_rows(rows_df, scaler, iso_forest, lof, feature_cols, score_ranges):
    """
    Score behavior rows using the trained models.

    This function is used by detect_anomaly.py.

    Steps:
    1. Keep identity columns for explanation.
    2. Extract numeric behavior features.
    3. Scale features using the saved StandardScaler.
    4. Get predictions from the 2 models.
    5. Convert predictions into anomaly flags.
    6. Combine model votes.
    7. Save original features beside the result.
    """
    identity_df = rows_df[IDENTITY_COLS].copy()

    X = clean_feature_matrix(rows_df, feature_cols)
    """
    Use transform, not fit_transform, during detection.
    fit_transform is used during training because it learns the mean and standard
    deviation from the training data, then scales the data using those learned values.
    During detection, we do not want to learn a new mean and standard deviation from
    the new row. Instead, we want to use the same scaling rules that were learned
    from the training data. This makes the new row comparable to the behavior the
    model was trained on.
    If we used fit_transform on the new row, the scaler would adapt to that row and
    make it look normal compared to itself. This could hide the anomaly. We want to
    detect whether the new row is abnormal compared to the training behavior, not
    make the preprocessing fit the new row.
    """
    X_scaled = scaler.transform(X)
    """
    X        = original numeric behavior features
    X_scaled = normalized version of those features ready for the ML models
    
    """
    # ------------------------------
    # Predictions
    # ------------------------------

    if_predictions = iso_forest.predict(X_scaled)
    lof_predictions = lof.predict(X_scaled)
    """
    .predict() is a method that belongs to each trained model object.

    iso_forest, and lof are trained in train_model.py,
    saved inside model_artifacts.joblib, then loaded in detect_anomaly.py
    and passed into this function.
    """
    if_anomaly = sklearn_prediction_to_flag(if_predictions)
    lof_anomaly = sklearn_prediction_to_flag(lof_predictions)


    # ------------------------------
    # Scores
    # ------------------------------
    # decision_function usually means:
    # higher = more normal
    #
    # We multiply by -1 so:
    # higher = more suspicious

    if_score = -iso_forest.decision_function(X_scaled)
    lof_score = -lof.decision_function(X_scaled)

    # ------------------------------
    # Build result table
    # ------------------------------
    results = identity_df.reset_index(drop=True)

    results["if_anomaly"] = if_anomaly
    results["lof_anomaly"] = lof_anomaly

    results["if_score"] = if_score
    results["lof_score"] = lof_score


    # ------------------------------
    # Ensemble voting
    # ------------------------------

    # Count how many models classified the row as anomalous.
    # Possible values:
    # AFTER
    # 0 = no model detected anomaly
    # 1 = one model detected anomaly
    # 2 = both models detected anomaly
    results["ensemble_votes"] = (
        results["if_anomaly"]
        + results["lof_anomaly"]
    )


    # ------------------------------
    # Ensemble score
    # ------------------------------

    # Convert each model's raw anomaly score into a readable 0 to 1 range.
    # Higher means more suspicious.
    results["if_score_scaled"] = scale_scores_with_training_range(
        results["if_score"],
        score_ranges["if_score_min"],
        score_ranges["if_score_max"]
    )

    results["lof_score_scaled"] = scale_scores_with_training_range(
        results["lof_score"],
        score_ranges["lof_score_min"],
        score_ranges["lof_score_max"]
    )

    
    # Average the 2 scaled model scores.
    # This gives one overall suspicion score.
    results["ensemble_score"] = (
        results["if_score_scaled"]
        + results["lof_score_scaled"]
    ) / 2


    # ------------------------------
    # Final anomaly decision
    # ------------------------------

    VOTE_THRESHOLD = 2
    SCORE_THRESHOLD = 0.75

    # A row is anomalous if:
    # 1. Two or more models vote anomaly
    # OR
    # 2. The average suspicion score is high enough
    results["final_anomaly"] = (
        (results["ensemble_votes"] >= VOTE_THRESHOLD)
        |
        (results["ensemble_score"] >= SCORE_THRESHOLD)
    ).astype(int)

    results["detection_reason"] = np.where(
        results["ensemble_votes"] >= VOTE_THRESHOLD,
        "model_vote",
        np.where(
            results["ensemble_score"] >= SCORE_THRESHOLD,
            "high_ensemble_score",
            "normal"
        )
    )
    # ------------------------------
    # Alert severity
    # ------------------------------

    def assign_severity(row):

        if row["ensemble_votes"] == 2:
            return "high"

        if row["ensemble_votes"] == 0:
            return "normal"

        if row["ensemble_score"] >= 0.85:
            return "medium"

        if row["ensemble_score"] >= 0.70:
            return "low"

        return "normal"


    results["severity"] = results.apply(assign_severity, axis=1)
    # final_anomaly becomes 1 if:
    # 1. two or more models vote anomaly
    # OR
    # 2. the ensemble_score is above the score threshold.
    final_results = pd.concat(
        [
            results,
            X.reset_index(drop=True)
        ],
        axis=1
    )

    return final_results


def upsert_results(old_results, new_results):
    """
    Add new results into model_results.csv without duplicates.

    If the same:
    user_name + host_name + window_start

    already exists, keep the newest result.
    """

    combined = pd.concat(
        [old_results, new_results],
        ignore_index=True
    )

    combined = parse_window_start(combined)

    combined = combined.drop_duplicates(
        subset=IDENTITY_COLS,
        keep="last"
    )
    """
    subset=IDENTITY_COLS tells pandas to check duplicates using only the columns
    inside IDENTITY_COLS, which are user_name, host_name, and window_start.

    So two rows are considered duplicates if these three values are the same,
    even if other columns like scores, votes, or final_anomaly are different.

    keep="last" tells pandas to keep the last duplicated row and remove the earlier
    ones. Since we combine old_results first and new_results second, the last row is
    the newer detection result.
    """
    combined = combined.sort_values(
        by=[
            "user_name",
            "host_name",
            "window_start"
        ]
    ).reset_index(drop=True)

    return combined