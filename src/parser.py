import re


def parse_log_line(line):

    pattern = (
        r"(\w{3})\s+(\d{1,2})\s+"
        r"(\d{2}:\d{2}:\d{2}).*"
        r"(Failed|Accepted) password for (\w+) from "
        r"(\d{1,3}(?:\.\d{1,3}){3})"
    )

    match = re.search(pattern, line)

    if match:
        month = match.group(1)
        day = match.group(2)
        time = match.group(3)
        status = match.group(4)
        user = match.group(5)
        ip = match.group(6)

        return {
            "date": f"{month} {day}",
            "time": time,
            "status": status.lower(),
            "user": user,
            "ip": ip
        }

    return None
