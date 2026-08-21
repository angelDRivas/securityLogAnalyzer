from pathlib import Path

import pandas as pd

from parser import parse_log_line
from analyzer import (
    get_summary,
    get_top_failed_ips,
    get_most_targeted_users,
    detect_suspicious_ips,
    detect_brute_force,
)


BASE_DIR = Path(__file__).resolve().parent.parent

LOG_FILE = BASE_DIR / "data" / "sample_auth.log"
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_FILE = OUTPUT_DIR / "parsed_logs.csv"


def load_logs(log_file):
    """Read and parse supported authentication events."""

    events = []

    with open(log_file, "r", encoding="utf-8") as file:
        for line in file:
            event = parse_log_line(line)

            if event:
                events.append(event)

    return events


def main():
    print("\n=== SECURITY LOG ANALYZER ===")

    if not LOG_FILE.exists():
        print(f"\n[ERROR] Log file not found: {LOG_FILE}")
        return

    events = load_logs(LOG_FILE)

    if not events:
        print("\nNo supported authentication events were found.")
        return

    df = pd.DataFrame(events)

    # General summary
    summary = get_summary(df)

    print("\n=== SUMMARY ===")
    print("Total events:", summary["total_events"])
    print("Failed login attempts:", summary["failed_logins"])
    print("Successful login attempts:", summary["successful_logins"])
    print(
        "Failed login percentage:",
        f'{summary["failed_percentage"]:.2f}%',
    )

    # Failed attempts by IP
    print("\n=== TOP FAILED LOGIN IPS ===")

    top_ips = get_top_failed_ips(df)

    if top_ips.empty:
        print("No failed login attempts detected.")
    else:
        for ip, attempts in top_ips.items():
            print(f"{ip}: {attempts}")

    # Most targeted users
    print("\n=== MOST TARGETED USERS ===")

    targeted_users = get_most_targeted_users(df)

    if targeted_users.empty:
        print("No targeted users detected.")
    else:
        for user, attempts in targeted_users.items():
            print(f"{user}: {attempts}")

    # Suspicious IP detection
    print("\n=== SUSPICIOUS IPS ===")

    suspicious_ips = detect_suspicious_ips(df, threshold=4)

    if suspicious_ips.empty:
        print("No suspicious IP addresses detected.")
    else:
        for ip, attempts in suspicious_ips.items():
            print(
                f"[ALERT] {ip} - "
                f"{attempts} failed login attempts"
            )

    # Brute-force detection
    print("\n=== BRUTE-FORCE DETECTION ===")

    attacks = detect_brute_force(df, threshold=5)

    if not attacks:
        print("No potential brute-force attacks detected.")
    else:
        for attack in attacks:
            print(
                f'[{attack["severity"]}] '
                f'{attack["ip"]} - '
                f'{attack["attempts"]} failed attempts - '
                f'{attack["targeted_users"]} targeted users'
            )

    # Export parsed events
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    df.to_csv(OUTPUT_FILE, index=False)

    print(f"\nReport saved to: {OUTPUT_FILE}")
    print("\nAnalysis completed.")


if __name__ == "__main__":
    main()
