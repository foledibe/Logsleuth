"""
log_parser.py

Turns raw, messy log text into clean, structured Python data.

A log line looks like this:
    Aug 10 03:14:15 prod-server sshd[4821]: Failed password for invalid user admin from 203.0.113.77 port 51000 ssh2

We use "regular expressions" (regex) to pull the useful pieces out of
that sentence: the time, whether it succeeded or failed, the username,
and the IP address. Think of regex as a very precise "find and grab"
pattern-matcher for text.
"""

import re

# Pattern for a FAILED login attempt (optionally against an invalid user)
FAILED_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+Failed password for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+) ssh2"
)

# Pattern for a SUCCESSFUL login
ACCEPTED_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\S+\s+sshd\[\d+\]:\s+Accepted password for "
    r"(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+) ssh2"
)


def _hour_from_time(time_str):
    """'03:14:15' -> 3 (as an integer, so we can compare hours easily)."""
    return int(time_str.split(":")[0])


def parse_line(raw_line):
    """
    Try to turn one raw log line into a dictionary of structured data.
    Returns None if the line doesn't match anything we recognize
    (real logs have lots of lines we don't care about, and that's fine).
    """
    match = FAILED_PATTERN.match(raw_line)
    if match:
        return {
            "status": "failed",
            "user": match.group("user"),
            "invalid_user": match.group("invalid") is not None,
            "ip": match.group("ip"),
            "time": match.group("time"),
            "hour": _hour_from_time(match.group("time")),
        }

    match = ACCEPTED_PATTERN.match(raw_line)
    if match:
        return {
            "status": "accepted",
            "user": match.group("user"),
            "invalid_user": False,
            "ip": match.group("ip"),
            "time": match.group("time"),
            "hour": _hour_from_time(match.group("time")),
        }

    return None


def parse_log(filepath):
    """
    Read an entire log file and return a list of structured event
    dictionaries. Lines we don't recognize are silently skipped.
    """
    events = []
    with open(filepath, "r") as f:
        for raw_line in f:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            event = parse_line(raw_line)
            if event:
                events.append(event)
    return events
