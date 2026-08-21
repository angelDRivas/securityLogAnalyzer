import re


def parse_log_line(line):
    """
    Parse a Linux SSH authentication log line.

    Returns a dictionary containing the extracted information
    or None when the line does not match a supported event.
    """

    pattern = (
        r"(\w{3})\s+(\d{1,2})\s+"
        r"(\d{2}:\d{2}:\d{2}).*?"
        r"(Failed|Accepted) password for "
        r"(?:(invalid user)\s+)?"
        r"([\w.-]+) from "
        r"(\d{1,3}(?:\.\d{1,3}){3})"
    )

    match = re.search(pattern, line)

    if not match:
        return None

    month = match.group(1)
    day = match.group(2)
    time = match.group(3)
    status = match.group(4).lower()
    invalid_user = match.group(5) is not None
    user = match.group(6)
    ip = match.group(7)

    return {
        "date": f"{month} {day}",
        "time": time,
        "status": status,
        "user": user,
        "ip": ip,
        "invalid_user": invalid_user,
    }
