import os
import sys

import pandas as pd

# Add src/ to Python path so package imports work when running this file directly.
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, SRC_DIR)

from data_collection.pull import get_logs


# ==============================================================================
# CONFIGURATION
# ==============================================================================

LOG_PULL_SIZE = 9000
LOG_LOOKBACK = "now-1d"
WINDOW_SIZE = "10min"
LOCAL_TIMEZONE = "Africa/Cairo"

OUTPUT_CSV_PATH = os.path.join(
    os.path.dirname(__file__),
    "behavior_dataset.csv"
)

# Optional single-user lab fallback.
# If some Windows logon events do not contain a real username, they can be mapped
# to a known lab user for a controlled single-user environment.
# Change these values locally if needed. Keep generic values in the public repo.
ENABLE_SINGLE_USER_LAB_FALLBACK = False
LAB_HOSTNAME = "host_01"
LAB_PRIMARY_USER = "user_01"

SYSTEM_ACCOUNTS = {
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "ANONYMOUS LOGON",
    "-",
    "",
    None
}

EXCLUDED_USERS = [
    "SYSTEM",
    "LOCAL SERVICE",
    "NETWORK SERVICE",
    "Administrator",
    "DefaultAccount",
    "Guest",
    "Guest1",
    "WDAGUtilityAccount",
    "-",
    None,
    "DWM-1",
    "DWM-2",
    "DWM-3",
    "UMFD-0",
    "UMFD-1",
    "UMFD-2",
    "Administrators",
    "Backup Operators",
]

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".js",
    ".scr"
}

SUSPICIOUS_PATH_KEYWORDS = [
    "startup",
    "programdata",
]

# Same person may appear under different identity formats.
# Keep this generic in the public repository.
# Example:
# {
#     "user01@example.com": "user_01",
#     "HOSTNAME\\user_01": "user_01",
# }
IDENTITY_MAP = {
    "user01@example.com": "user_01",
}


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def extract_sysmon_user(value):
    """
    Normalize Sysmon user format.

    Sysmon may store usernames as:
    DOMAIN\\username
    HOSTNAME\\username

    This function keeps only the final username part.
    """

    if not isinstance(value, str) or not value:
        return None

    return value.split("\\")[-1] if "\\" in value else value


def contains(value, keyword):
    """
    Case-insensitive substring check.
    """

    return (
        isinstance(value, str)
        and keyword in value.lower()
    )


def is_real_user(username):
    """
    Return True if the username looks like a real user account rather than a
    Windows internal, service, or machine account.
    """

    if username in SYSTEM_ACCOUNTS:
        return False

    if str(username).endswith("$"):
        return False

    return True


def get_attributed_user(event_data):
    """
    Determine the best available user attribution from Windows/Sysmon fields.

    Windows events may store usernames in different fields depending on the
    event type. The priority used here is:
    1. SubjectUserName
    2. TargetUserName
    3. Sysmon User fallback
    """

    subject = event_data.get("SubjectUserName", "")
    target = event_data.get("TargetUserName", "")
    sysmon_user_raw = event_data.get("User", "")
    sysmon_user_clean = extract_sysmon_user(sysmon_user_raw)

    if is_real_user(subject):
        return subject, sysmon_user_raw

    if is_real_user(target):
        return target, sysmon_user_raw

    if is_real_user(sysmon_user_clean):
        return sysmon_user_clean, sysmon_user_raw

    return None, sysmon_user_raw


def get_suspicious_file_flag(target_filename):
    """
    Flag suspicious file creation based on extension or location.

    This is a lightweight heuristic used for behavioral feature construction.
    """

    if not isinstance(target_filename, str):
        return 0

    lower_file = target_filename.lower()

    suspicious_extension = any(
        lower_file.endswith(extension)
        for extension in SUSPICIOUS_EXTENSIONS
    )

    suspicious_location = any(
        keyword in lower_file
        for keyword in SUSPICIOUS_PATH_KEYWORDS
    )

    return int(suspicious_extension or suspicious_location)


# ==============================================================================
# STEP 1: PULL RAW LOGS FROM ELASTICSEARCH
# ==============================================================================

logs = get_logs(size=LOG_PULL_SIZE, lookback=LOG_LOOKBACK)

rows = []

for log in logs:

    event_data = log.get("winlog", {}).get("event_data", {})
    event = log.get("event", {})
    host = log.get("host", {})

    user_name, sysmon_user_raw = get_attributed_user(event_data)

    row = {
        "timestamp": log.get("@timestamp"),
        "user_name": user_name,
        "sysmon_user": sysmon_user_raw,
        "credentials_returned": event_data.get("CountOfCredentialsReturned"),
        "host_name": host.get("name"),
        "event_code": str(event.get("code", "")),
        "event_action": event.get("action", ""),
        "process_name": event_data.get("Image"),
        "parent_process": event_data.get("ParentImage"),
        "logon_type": event_data.get("LogonType"),
        "suspicious_file_flag": get_suspicious_file_flag(
            event_data.get("TargetFilename", "")
        ),
    }

    rows.append(row)

df = pd.DataFrame(rows)


# ==============================================================================
# STEP 2: BASIC CLEANING
# ==============================================================================

if df.empty:
    raise ValueError("No logs were pulled from Elasticsearch.")

df["credentials_returned"] = pd.to_numeric(
    df["credentials_returned"],
    errors="coerce"
).fillna(0)

df["sysmon_user_clean"] = (
    df["sysmon_user"]
    .apply(extract_sysmon_user)
)

df["user_name"] = (
    df["user_name"]
    .fillna(df["sysmon_user_clean"])
)


# ==============================================================================
# STEP 3: OPTIONAL SINGLE-USER LAB FALLBACK
# ==============================================================================

if ENABLE_SINGLE_USER_LAB_FALLBACK:

    df["user_name"] = df.apply(
        lambda row: LAB_PRIMARY_USER
        if (
            pd.isna(row["user_name"])
            and row["event_code"] in ["4624", "4625"]
            and row["host_name"] == LAB_HOSTNAME
        )
        else row["user_name"],
        axis=1
    )

# Drop rows that still do not have a usable user attribution.
df = df[df["user_name"].notna()]


# ==============================================================================
# STEP 4: TIME PROCESSING
# ==============================================================================

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    utc=True,
    errors="coerce"
)

df = df[df["timestamp"].notna()]

df["timestamp"] = (
    df["timestamp"]
    .dt.tz_convert(LOCAL_TIMEZONE)
)

df["window_start"] = (
    df["timestamp"]
    .dt.floor(WINDOW_SIZE)
)


# ==============================================================================
# STEP 5: EVENT FLAGS
# ==============================================================================

df["process_flag"] = (
    (df["event_code"] == "1") |
    df["event_action"].str.startswith("Process Create", na=False)
).astype(int)

df["network_flag"] = (
    (df["event_code"] == "3") |
    df["event_action"].str.startswith("Network connection detected", na=False)
).astype(int)

df["file_flag"] = (
    (df["event_code"] == "11") |
    df["event_action"].str.startswith("File created", na=False)
).astype(int)

df["powershell_flag"] = (
    df["process_name"]
    .apply(lambda value: int(contains(value, "powershell")))
)

df["cmd_flag"] = (
    df["process_name"]
    .apply(lambda value: int(contains(value, "cmd.exe")))
)

df["susp_parent_flag"] = (
    df["parent_process"]
    .apply(
        lambda value: int(
            contains(value, "winword")
            or contains(value, "excel")
            or contains(value, "outlook")
            or contains(value, "mshta")
            or contains(value, "wscript")
            or contains(value, "cscript")
        )
    )
)


# ==============================================================================
# STEP 6: FEATURE AGGREGATION
# ==============================================================================

grouped = df.groupby(
    ["user_name", "host_name", "window_start"]
).agg(

    successful_login_count=(
        "event_code",
        lambda values: (values == "4624").sum()
    ),

    failed_login_count=(
        "event_code",
        lambda values: (values == "4625").sum()
    ),

    credential_access_count=(
        "event_code",
        lambda values: (values == "5379").sum()
    ),

    credential_access_volume=(
        "credentials_returned",
        "sum"
    ),

    process_creation_count=(
        "process_flag",
        "sum"
    ),

    unique_process_count=(
        "process_name",
        "nunique"
    ),

    powershell_exec_count=(
        "powershell_flag",
        "sum"
    ),

    cmd_exec_count=(
        "cmd_flag",
        "sum"
    ),

    suspicious_parent_count=(
        "susp_parent_flag",
        "sum"
    ),

    network_connection_count=(
        "network_flag",
        "sum"
    ),

    file_creation_count=(
        "file_flag",
        "sum"
    ),

    suspicious_file_creation_count=(
        "suspicious_file_flag",
        "sum"
    ),

    unique_login_types=(
        "logon_type",
        "nunique"
    ),

).reset_index()


# ==============================================================================
# STEP 7: REMOVE SYSTEM / SERVICE ACCOUNTS
# ==============================================================================

grouped = grouped[
    ~grouped["user_name"].isin(EXCLUDED_USERS)
]

grouped = grouped[
    ~grouped["user_name"].str.endswith("$", na=False)
]


# ==============================================================================
# STEP 8: UNIFY USER IDENTITIES
# ==============================================================================

grouped["user_name"] = (
    grouped["user_name"]
    .replace(IDENTITY_MAP)
)


# ==============================================================================
# STEP 9: RE-AGGREGATE AFTER IDENTITY MERGE
# ==============================================================================

numeric_cols = [
    "successful_login_count",
    "failed_login_count",
    "credential_access_count",
    "credential_access_volume",
    "process_creation_count",
    "unique_process_count",
    "powershell_exec_count",
    "cmd_exec_count",
    "suspicious_parent_count",
    "network_connection_count",
    "file_creation_count",
    "suspicious_file_creation_count",
    "unique_login_types",
]

grouped = grouped.groupby(
    ["user_name", "host_name", "window_start"]
)[numeric_cols].sum().reset_index()


# ==============================================================================
# STEP 10: DERIVED FEATURES
# ==============================================================================

grouped["failed_success_ratio"] = (
    grouped["failed_login_count"]
    /
    (grouped["successful_login_count"] + 1)
)

grouped["credential_volume_per_read"] = (
    grouped["credential_access_volume"]
    /
    (grouped["credential_access_count"] + 1)
)

grouped["process_diversity_ratio"] = (
    grouped["unique_process_count"]
    /
    (grouped["process_creation_count"] + 1)
)

grouped["shell_ratio"] = (
    (
        grouped["powershell_exec_count"]
        +
        grouped["cmd_exec_count"]
    )
    /
    (grouped["process_creation_count"] + 1)
)

grouped["network_per_process"] = (
    grouped["network_connection_count"]
    /
    (grouped["process_creation_count"] + 1)
)

grouped["file_per_process"] = (
    grouped["file_creation_count"]
    /
    (grouped["process_creation_count"] + 1)
)

grouped["activity_hour"] = (
    pd.to_datetime(grouped["window_start"])
    .dt.hour
)

grouped["weekend_activity"] = (
    pd.to_datetime(grouped["window_start"])
    .dt.weekday >= 5
).astype(int)


# ==============================================================================
# STEP 11: FINAL COLUMN ORDER
# ==============================================================================

final_columns = [
    "user_name",
    "host_name",
    "window_start",

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

grouped = grouped[final_columns]


# ==============================================================================
# STEP 12: SAVE / UPSERT HISTORY
# ==============================================================================

if os.path.exists(OUTPUT_CSV_PATH):

    existing = pd.read_csv(OUTPUT_CSV_PATH)

    existing["window_start"] = pd.to_datetime(
        existing["window_start"]
    )

    grouped["window_start"] = pd.to_datetime(
        grouped["window_start"]
    )

    output_df = pd.concat(
        [existing, grouped],
        ignore_index=True
    )

    output_df = output_df.drop_duplicates(
        subset=[
            "user_name",
            "host_name",
            "window_start"
        ],
        keep="last"
    )

    output_df = output_df.sort_values(
        by=["user_name", "window_start"]
    ).reset_index(drop=True)

else:

    output_df = grouped.copy()


# Recompute derived features after merging historical and new rows.
output_df["failed_success_ratio"] = (
    output_df["failed_login_count"]
    /
    (output_df["successful_login_count"] + 1)
)

output_df["credential_volume_per_read"] = (
    output_df["credential_access_volume"]
    /
    (output_df["credential_access_count"] + 1)
)

output_df["process_diversity_ratio"] = (
    output_df["unique_process_count"]
    /
    (output_df["process_creation_count"] + 1)
)

output_df["shell_ratio"] = (
    (
        output_df["powershell_exec_count"]
        +
        output_df["cmd_exec_count"]
    )
    /
    (output_df["process_creation_count"] + 1)
)

output_df["network_per_process"] = (
    output_df["network_connection_count"]
    /
    (output_df["process_creation_count"] + 1)
)

output_df["file_per_process"] = (
    output_df["file_creation_count"]
    /
    (output_df["process_creation_count"] + 1)
)

output_df = output_df[final_columns]

output_df.to_csv(
    OUTPUT_CSV_PATH,
    index=False
)


# ==============================================================================
# STEP 13: OUTPUT SUMMARY
# ==============================================================================

print(f"[INFO] Dataset saved to        : {OUTPUT_CSV_PATH}")
print(f"[INFO] Total behavioral rows  : {len(output_df)}")
print(f"[INFO] Unique users found     : {list(output_df['user_name'].unique())}")
print(f"[INFO] Time range             : {output_df['window_start'].min()} → {output_df['window_start'].max()}")
print(f"[INFO] Columns                : {list(output_df.columns)}")
print()
print(output_df.to_string())