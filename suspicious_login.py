#!/usr/bin/env python3
import argparse, subprocess, re, csv, json
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Log Analyzer for SSH login attempts")
    parser.add_argument(
        "-s", "--source",
        choices=["authlog", "journalctl"],
        required=True,
        help="Select log source: 'authlog' for /var/log/auth.log or 'journalctl'"
    )
    parser.add_argument(
        "-t", "--type",
        choices=["failed", "accepted", "both"],
        default="failed",
        help="Type of login attempts to analyze (default: failed)"
    )
    parser.add_argument(
        "-o", "--output",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--group",
        action="store_true",
        help="Group failed attempts by IP and username (only valid with failed/both)"
    )
    return parser.parse_args()

def read_authlog():
    path = Path("/var/log/auth.log")
    if not path.exists():
        print(Fore.RED + "/var/log/auth.log not found")
        exit(1)
    return path.read_text().splitlines()

def read_journalctl():
    try:
        output = subprocess.run(["journalctl", "-u", "ssh"], capture_output=True, text=True, check=True)
        return output.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(Fore.RED + "Error accessing journalctl:", e)
        exit(1)

def extract_attempts(log_lines, types):
    failed_pattern = re.compile(r"Failed password.*for(?: invalid user)? (\S+) from (\d+\.\d+\.\d+\.\d+)")
    accepted_pattern = re.compile(r"Accepted password.*for (\S+) from (\d+\.\d+\.\d+\.\d+)")

    attempts = []

    for line in log_lines:
        timestamp = " ".join(line.split()[:3])
        if "Failed password" in line and types in ("failed", "both"):
            m = failed_pattern.search(line)
            if m:
                attempts.append({
                    "timestamp": timestamp,
                    "status": "failed",
                    "username": m.group(1),
                    "ip": m.group(2)
                })
        elif "Accepted password" in line and types in ("accepted", "both"):
            m = accepted_pattern.search(line)
            if m:
                attempts.append({
                    "timestamp": timestamp,
                    "status": "accepted",
                    "username": m.group(1),
                    "ip": m.group(2)
                })

    return attempts

def group_failed_attempts(attempts):
    counts = defaultdict(int)
    for entry in attempts:
        if entry["status"] == "failed":
            key = (entry['ip'], entry['username'])
            counts[key] += 1

    grouped = [
        {"ip": ip, "username": user, "attempts": count}
        for (ip, user), count in counts.items()
    ]
    return grouped

def output_results(data, format):
    if not data:
        print(Fore.GREEN + "✅ No matching SSH login attempts found.")
        return

    if format == "json":
        print(json.dumps(data, indent=2))
    else:
        keys = data[0].keys()
        with open("ssh_login_attempts.csv", "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        print(Fore.GREEN + "✅ Output saved to ssh_login_attempts.csv")

def main():
    args = parse_arguments()
    log_lines =read_authlog() if args.source == "authlog" else read_journalctl()
    attempts = extract_attempts(log_lines, args.type)

    if args.group and args.type in ("failed", "both"):
        grouped = group_failed_attempts(attempts)
        output_results(grouped, args.output)
    else:
        output_results(attempts, args.output)

if __name__ == "__main__":
    main()

# Force update by Thiruvarul
