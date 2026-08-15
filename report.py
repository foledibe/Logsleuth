"""
report.py

Takes the raw events + the detector results and turns them into
something a human can actually read: a console summary, and
(optionally) a JSON file another tool could consume later.
"""

import json


def _risk_label(score):
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def print_console_report(events, results):
    failed_count = sum(1 for e in events if e["status"] == "failed")
    accepted_count = sum(1 for e in events if e["status"] == "accepted")

    print("=" * 60)
    print("  LOGSLEUTH REPORT")
    print("=" * 60)
    print(f"Total log lines parsed:       {len(events)}")
    print(f"Failed login attempts:        {failed_count}")
    print(f"Successful logins:            {accepted_count}")
    print()

    print("🔨 BRUTE-FORCE SUSPECTS (5+ failed attempts)")
    if results["brute_force"]:
        for ip, count in results["brute_force"].items():
            print(f"  {ip:<18}  →  {count} failed attempts")
    else:
        print("  None detected.")
    print()

    print("👻 INVALID USER PROBES")
    if results["invalid_user_probes"]:
        for ip, user in results["invalid_user_probes"]:
            print(f"  {ip} tried user '{user}'")
    else:
        print("  None detected.")
    print()

    print("🌙 OFF-HOURS SUCCESSFUL LOGINS")
    if results["off_hours_logins"]:
        for e in results["off_hours_logins"]:
            print(f"  {e['user']} logged in successfully at {e['time']} from {e['ip']}")
    else:
        print("  None detected.")
    print()

    label = _risk_label(results["risk_score"])
    print(f"Overall risk score: {results['risk_score']}/10 ({label})")
    print("=" * 60)


def export_json_report(events, results, filepath):
    """Write the findings to a JSON file so another tool (or a resume demo!) can use them."""
    payload = {
        "total_events": len(events),
        "failed_attempts": sum(1 for e in events if e["status"] == "failed"),
        "successful_logins": sum(1 for e in events if e["status"] == "accepted"),
        "brute_force_suspects": results["brute_force"],
        "invalid_user_probes": [
            {"ip": ip, "user": user} for ip, user in results["invalid_user_probes"]
        ],
        "off_hours_logins": results["off_hours_logins"],
        "risk_score": results["risk_score"],
        "risk_label": _risk_label(results["risk_score"]),
    }
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\nJSON report saved to {filepath}")
