"""
test_threat_detector.py

Unit tests for the detection rules. These don't need a real log file —
we just build small lists of fake "events" by hand, since that's exactly
what log_parser.py would have produced from real log lines.

Run with:  python -m unittest discover tests
"""

import sys
import os
import unittest

# Let this test file import modules from the project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from threat_detector import (
    detect_brute_force,
    detect_invalid_user_probes,
    detect_off_hours_logins,
    compute_risk_score,
)


def make_event(status, ip, user="root", hour=12, invalid_user=False, time="12:00:00"):
    return {
        "status": status,
        "ip": ip,
        "user": user,
        "hour": hour,
        "invalid_user": invalid_user,
        "time": time,
    }


class TestBruteForceDetection(unittest.TestCase):
    def test_flags_ip_over_threshold(self):
        events = [make_event("failed", "1.2.3.4") for _ in range(6)]
        result = detect_brute_force(events, threshold=5)
        self.assertIn("1.2.3.4", result)
        self.assertEqual(result["1.2.3.4"], 6)

    def test_does_not_flag_ip_under_threshold(self):
        events = [make_event("failed", "1.2.3.4") for _ in range(3)]
        result = detect_brute_force(events, threshold=5)
        self.assertNotIn("1.2.3.4", result)

    def test_ignores_successful_logins(self):
        events = [make_event("accepted", "1.2.3.4") for _ in range(10)]
        result = detect_brute_force(events, threshold=5)
        self.assertEqual(result, {})


class TestInvalidUserProbes(unittest.TestCase):
    def test_finds_invalid_user_attempts(self):
        events = [
            make_event("failed", "1.2.3.4", user="admin", invalid_user=True),
            make_event("failed", "1.2.3.4", user="root", invalid_user=False),
        ]
        result = detect_invalid_user_probes(events)
        self.assertEqual(result, [("1.2.3.4", "admin")])


class TestOffHoursLogins(unittest.TestCase):
    def test_flags_login_at_3am(self):
        events = [make_event("accepted", "1.2.3.4", hour=3, time="03:14:15")]
        result = detect_off_hours_logins(events)
        self.assertEqual(len(result), 1)

    def test_does_not_flag_login_at_noon(self):
        events = [make_event("accepted", "1.2.3.4", hour=12, time="12:00:00")]
        result = detect_off_hours_logins(events)
        self.assertEqual(result, [])


class TestRiskScore(unittest.TestCase):
    def test_score_is_zero_when_nothing_found(self):
        self.assertEqual(compute_risk_score({}, [], []), 0)

    def test_score_increases_with_findings(self):
        brute_force = {"1.2.3.4": 10}
        invalid_users = [("1.2.3.4", "admin")]
        off_hours = [make_event("accepted", "1.2.3.4")]
        score = compute_risk_score(brute_force, invalid_users, off_hours)
        self.assertGreater(score, 0)


if __name__ == "__main__":
    unittest.main()
