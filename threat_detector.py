"""
threat_detector.py

This is the "brain" of LogSleuth — the actual rules that decide
whether something in the log looks suspicious.

Each function takes the list of parsed events (from log_parser.py)
and returns whatever it found. Keeping each rule in its own small
function makes it easy to add new rules later without breaking the
old ones.
"""

from collections import Counter, defaultdict

OFF_HOURS_START = 0   # midnight
OFF_HOURS_END = 5     # 5 AM


def detect_brute_force(events, threshold=5):
    """
    Rule: if one IP address has `threshold` or more FAILED login
    attempts, treat it as a brute-force suspect.

    Returns a dict like: {"203.0.113.77": 14}
    """
    failed_ip_counts = Counter(
        e["ip"] for e in events if e["status"] == "failed"
    )
    return {
        ip: count
        for ip, count in failed_ip_counts.items()
        if count >= threshold
    }


def detect_invalid_user_probes(events):
    """
    Rule: flag every attempt to log in as a username that doesn't
    exist on the system. Attackers often "spray" common usernames
    (admin, test, root, oracle...) hoping one exists.

    Returns a list of (ip, user) tuples.
    """
    return [
        (e["ip"], e["user"])
        for e in events
        if e["status"] == "failed" and e["invalid_user"]
    ]


def detect_off_hours_logins(events):
    """
    Rule: flag SUCCESSFUL logins that happened between midnight and
    5 AM. A successful login itself isn't automatically bad, but one
    that happens at 3 AM when no employee should be awake is worth a
    second look.

    Returns a list of matching event dicts.
    """
    return [
        e for e in events
        if e["status"] == "accepted"
        and OFF_HOURS_START <= e["hour"] < OFF_HOURS_END
    ]


def compute_risk_score(brute_force_hits, invalid_user_hits, off_hours_hits):
    """
    A very simple 0-10 scoring model, just to demonstrate how you'd
    turn raw findings into a single number a manager could glance at.

    This is intentionally simple — a real SOC tool would weigh things
    like attempt volume, whether the attack succeeded, asset criticality,
    etc. Here we keep it readable.
    """
    score = 0
    score += min(len(brute_force_hits) * 3, 6)      # up to 6 points
    score += min(len(invalid_user_hits) * 0.3, 2)   # up to 2 points
    score += min(len(off_hours_hits) * 2, 2)        # up to 2 points
    return round(min(score, 10))


def run_all_detectors(events, brute_force_threshold=5):
    """Convenience function that runs every rule and bundles the results."""
    brute_force = detect_brute_force(events, threshold=brute_force_threshold)
    invalid_users = detect_invalid_user_probes(events)
    off_hours = detect_off_hours_logins(events)
    risk_score = compute_risk_score(brute_force, invalid_users, off_hours)

    return {
        "brute_force": brute_force,
        "invalid_user_probes": invalid_users,
        "off_hours_logins": off_hours,
        "risk_score": risk_score,
    }
