from parser import parse_log_line
from analyzer import (
    get_summary,
    get_top_failed_ips,
    get_most_targeted_users,
    detect_suspicious_ips
)

import pandas as pd


log_file = "data/sample_auth.log"

events = []

with open(log_file, "r") as file:
    for line in file:
        event = parse_log_line(line)

        if event:
            events.append(event)


df = pd.DataFrame(events)

summary = get_summary(df)

print("\n=== SECURITY LOG ANALYZER ===")

print("\nSummary")
print("Total events:", summary["total_events"])
print("Failed login attempts:", summary["failed_logins"])
print("Successful login attempts:", summary["successful_logins"])
print(
    "Failed login percentage:",
    f'{summary["failed_percentage"]:.2f}%'
)


print("\nFailed attempts by IP:")
print(get_top_failed_ips(df))


print("\nMost targeted users:")
print(get_most_targeted_users(df))


df.to_csv("output/parsed_logs.csv", index=False)


suspicious_ips = detect_suspicious_ips(df, threshold = 4)

for ip, attempts in suspicious_ips.items():
    print(f"[ALERT] {ip} - {attempts} failed login attempts")

if suspicious_ips.empty:
    print("No suspicious activity detected.")
else:
    print(suspicious_ips)
