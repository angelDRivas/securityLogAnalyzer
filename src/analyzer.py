def get_summary(df):
    total_events = len(df)

    failed_logins = df[df["status"] == "failed"]
    successful_logins = df[df["status"] == "accepted"]

    failed_count = len(failed_logins)
    successful_count = len(successful_logins)

    failed_percentage = 0

    if total_events > 0:
        failed_percentage = (failed_count / total_events) * 100

    return {
        "total_events": total_events,
        "failed_logins": failed_count,
        "successful_logins": successful_count,
        "failed_percentage": failed_percentage
    }


def get_top_failed_ips(df):
    failed_logins = df[df["status"] == "failed"]

    return failed_logins["ip"].value_counts()


def get_most_targeted_users(df):
    failed_logins = df[df["status"] == "failed"]

    return failed_logins["user"].value_counts()

def detect_suspicious_ips(df, threshold=3):
    failed_logins = df[df["status"] == "failed"]

    failed_by_ip = failed_logins["ip"].value_counts()

    suspicious_ips = failed_by_ip[failed_by_ip >= threshold]

    return suspicious_ips
