# 🕵️ LogSleuth

**A lightweight Python tool that reads server login logs and sniffs out suspicious activity — brute-force attempts, logins to accounts that don't exist, and logins at weird hours of the night.**

Think of it as a detective that reads through a giant pile of server "diary entries" (logs) and circles the ones that look shady.

---

## Why I built this

Servers write down every login attempt in a log file — who tried to log in, from what IP address, whether it worked, and when. Attackers show up in these logs too, usually as a *pattern*: dozens of failed logins in a few seconds, or someone trying to log in as "admin," "root," or "test" over and over.

LogSleuth automates the boring part (reading thousands of log lines) so a human analyst can focus on the interesting part (deciding what to do about the threats).

## What it detects

| Threat | How it's found |
|---|---|
| 🔨 **Brute-force attempts** | Same IP address racks up N+ failed logins |
| 👻 **Invalid user probing** | Login attempts for usernames that don't exist on the system |
| 🌙 **Off-hours logins** | Successful logins between midnight and 5 AM (classic "nobody should be awake doing this" red flag) |

## How it works

```
sample_logs/auth.log  →  log_parser.py  →  threat_detector.py  →  report.py  →  console + JSON report
```

1. **`log_parser.py`** reads a raw SSH auth log and turns each line into a clean Python dictionary.
2. **`threat_detector.py`** runs three detection rules over those events.
3. **`report.py`** prints a readable summary table and can export the findings as JSON.
4. **`logsleuth.py`** is the command-line entry point that ties it all together.

## Quick start

```bash
# 1. Generate a fake (but realistic) log file to practice on
python generate_sample_log.py

# 2. Run the analyzer on it
python logsleuth.py sample_logs/auth.log

# 3. (optional) Export a JSON report
python logsleuth.py sample_logs/auth.log --export report.json
```

### Example output

```
============================================================
  LOGSLEUTH REPORT
============================================================
Total log lines parsed:       47
Failed login attempts:        21
Successful logins:            26

🔨 BRUTE-FORCE SUSPECTS (5+ failed attempts)
  203.0.113.77        →  14 failed attempts

👻 INVALID USER PROBES
  203.0.113.77 tried user 'admin'
  203.0.113.77 tried user 'test'
  203.0.113.77 tried user 'oracle'

🌙 OFF-HOURS SUCCESSFUL LOGINS
  root logged in successfully at 03:14:15 from 198.51.100.23

Overall risk score: 8/10 (HIGH)
============================================================
```

## Project structure

```
logsleuth/
├── generate_sample_log.py   # makes a realistic fake log file to test against
├── log_parser.py             # turns raw log lines into structured data
├── threat_detector.py        # the actual detection rules
├── report.py                 # console + JSON reporting
├── logsleuth.py               # CLI entry point
├── tests/
│   └── test_threat_detector.py
└── sample_logs/
    └── auth.log               # generated, not committed
```

## Why no external libraries?

Everything here uses only Python's standard library (`re`, `argparse`, `json`, `collections`, `datetime`). That was intentional — it keeps the project easy to read, easy to run anywhere, and keeps the focus on the *logic* of threat detection rather than dependency management.

## Possible next steps

- Add a rule for detecting logins from unusual geographic locations
- Support parsing real Apache/Nginx access logs, not just SSH auth logs
- Add a simple scoring weight config file so thresholds are tunable
- Turn the JSON report into a small HTML dashboard

## License

MIT — see `LICENSE`.
