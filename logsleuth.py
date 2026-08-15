"""
logsleuth.py

The command-line entry point. This is the file you actually run.

Usage:
    python logsleuth.py sample_logs/auth.log
    python logsleuth.py sample_logs/auth.log --threshold 3
    python logsleuth.py sample_logs/auth.log --export report.json
"""

import argparse
import sys

from log_parser import parse_log
from threat_detector import run_all_detectors
from report import print_console_report, export_json_report


def main():
    parser = argparse.ArgumentParser(
        description="LogSleuth — sniff out suspicious activity in SSH auth logs."
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Number of failed attempts from one IP before it's flagged as brute force (default: 5)",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Optional path to write a JSON report to",
    )
    args = parser.parse_args()

    try:
        events = parse_log(args.logfile)
    except FileNotFoundError:
        print(f"Error: could not find log file '{args.logfile}'")
        sys.exit(1)

    if not events:
        print("No recognizable log lines found. Is this an SSH auth log?")
        sys.exit(0)

    results = run_all_detectors(events, brute_force_threshold=args.threshold)
    print_console_report(events, results)

    if args.export:
        export_json_report(events, results, args.export)


if __name__ == "__main__":
    main()
