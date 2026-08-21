def get_summary(df):
    """Return general authentication statistics."""

    total_events = len(df)

    if total_events == 0:
        return {
            "total_events": 0,
            "failed_logins": 0,
            "successful_logins": 0,
            "failed_percentage": 0.0,
        }

    failed_count = (df["status"] == "failed").sum()
    successful_count = (df["status"] == "accepted").sum()

    failed_percentage = (failed_count / total_events) * 100

    return {
        "total_events": total_events,
        "failed_logins": int(failed_count),
        "successful_logins": int(successful_count),
        "failed_percentage": failed_percentage,
    }


def get_top_failed_ips(df, limit=5):
    """Return the IP addresses with the most failed login attempts."""

    failed_logins = df[df["status"] == "failed"]

    return failed_logins["ip"].value_counts().head(limit)


def get_most_targeted_users(df, limit=5):
    """Return the users with the most failed login attempts."""

    failed_logins = df[df["status"] == "failed"]

    return failed_logins["user"].value_counts().head(limit)


def detect_suspicious_ips(df, threshold=4):
    """
    Detect IP addresses exceeding a failed-login threshold.
    """

    failed_logins = df[df["status"] == "failed"]

    failed_by_ip = failed_logins["ip"].value_counts()

    return failed_by_ip[failed_by_ip >= threshold]


def detect_brute_force(df, threshold=5):
    """
    Detect potential brute-force activity.

    Returns information about IP addresses generating at least
    'threshold' failed login attempts.
    """

    failed_logins = df[df["status"] == "failed"]

    if failed_logins.empty:
        return []

    attacks = []

    grouped = failed_logins.groupby("ip")

    for ip, events in grouped:
        attempts = len(events)

        if attempts >= threshold:
            targeted_users = events["user"].nunique()

            if attempts >= threshold * 2:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            attacks.append(
                {
                    "ip": ip,
                    "attempts": attempts,
                    "targeted_users": targeted_users,
                    "severity": severity,
                }
            )

    attacks.sort(key=lambda attack: attack["attempts"], reverse=True)

    return attacks
