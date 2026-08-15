"""
generate_sample_log.py

Creates a fake (but realistic-looking) SSH auth log to practice on.

Real servers write a line every time someone tries to log in. We don't
have a real attacked server lying around, so this script pretends to be
one — it writes the SAME KIND of lines a real Linux server's
/var/log/auth.log would contain, including:

  - normal, boring, legitimate logins
  - a brute-force attack from one IP address
  - a few "invalid user" probes (attacker guessing usernames)
  - one suspicious successful login in the middle of the night

Run it with:  python generate_sample_log.py
"""

import os
import random

OUTPUT_PATH = os.path.join("sample_logs", "auth.log")

MONTHS = ["Aug"]
REAL_USERS = ["deploy", "backup-svc", "root"]
GUESSED_USERS = ["admin", "test", "oracle", "postgres", "ftpuser", "guest"]
LEGIT_IPS = ["10.0.0.5", "10.0.0.12", "192.168.1.20"]
ATTACKER_IP = "203.0.113.77"


def line(hour, minute, second, message):
    """Format one log line the way a real syslog entry looks."""
    day = random.randint(1, 28)
    month = random.choice(MONTHS)
    timestamp = f"{month} {day:>2} {hour:02d}:{minute:02d}:{second:02d}"
    return f"{timestamp} prod-server sshd[{random.randint(1000, 9999)}]: {message}"


def build_log():
    lines = []

    # --- A handful of totally normal logins during the workday ---
    for _ in range(8):
        user = random.choice(REAL_USERS)
        ip = random.choice(LEGIT_IPS)
        hour = random.randint(9, 17)  # normal work hours
        port = random.randint(40000, 60000)
        lines.append(
            line(hour, random.randint(0, 59), random.randint(0, 59),
                 f"Accepted password for {user} from {ip} port {port} ssh2")
        )

    # --- Occasional normal typo/failed login (people fat-finger passwords) ---
    for _ in range(3):
        user = random.choice(REAL_USERS)
        ip = random.choice(LEGIT_IPS)
        hour = random.randint(9, 17)
        port = random.randint(40000, 60000)
        lines.append(
            line(hour, random.randint(0, 59), random.randint(0, 59),
                 f"Failed password for {user} from {ip} port {port} ssh2")
        )

    # --- The brute-force attack: one IP, many rapid failed attempts ---
    attack_hour = 3  # attackers love the middle of the night
    minute = 14
    second = 0
    for _ in range(14):
        user = random.choice(GUESSED_USERS)
        port = random.randint(40000, 60000)
        lines.append(
            line(attack_hour, minute, second,
                 f"Failed password for invalid user {user} from {ATTACKER_IP} port {port} ssh2")
        )
        second += random.randint(1, 4)
        if second >= 60:
            second -= 60
            minute += 1

    # --- The scary part: right after the attack, ONE login succeeds ---
    # (imagine the attacker finally guessed right, or used a leaked password)
    lines.append(
        line(3, 14, 15, f"Accepted password for root from 198.51.100.23 port 51010 ssh2")
    )

    random.shuffle(lines)
    return lines


def main():
    os.makedirs("sample_logs", exist_ok=True)
    log_lines = build_log()
    with open(OUTPUT_PATH, "w") as f:
        f.write("\n".join(log_lines) + "\n")
    print(f"Wrote {len(log_lines)} log lines to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
