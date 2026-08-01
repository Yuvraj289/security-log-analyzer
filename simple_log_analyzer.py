"""
Simple Security Log Analyzer
=============================
Reads an SSH auth.log file and reports:
  1. How many times each IP address failed to log in
  2. Which IPs look like brute-force attackers (too many failures)
  3. Any IP that failed a lot AND then logged in successfully (suspicious!)

Usage:
    python simple_log_analyzer.py sample_auth.log
"""

import sys
import re
from collections import defaultdict

# Change this if you want a different failure threshold
FAILED_ATTEMPTS_THRESHOLD = 4

  # Regex patterns to pull data out of each log line
FAILED_PATTERN = re.compile(r"Failed password for(?: invalid user)? \S+ from (\d+\.\d+\.\d+\.\d+)")
SUCCESS_PATTERN = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def analyze_log(filename):
    failed_counts = defaultdict(int)   # ip -> number of failed attempts
    successful_logins = []             # list of (user, ip)

    with open(filename, "r") as f:
        for line in f:
            failed_match = FAILED_PATTERN.search(line)
            if failed_match:
                ip = failed_match.group(1)
                failed_counts[ip] += 1
                continue

            success_match = SUCCESS_PATTERN.search(line)
            if success_match:
                user, ip = success_match.groups()
                successful_logins.append((user, ip))

    return failed_counts, successful_logins


def print_report(failed_counts, successful_logins):
    print("=" * 50)
    print("SECURITY LOG REPORT")
    print("=" * 50)

    print("\nFailed login attempts by IP:")
    if failed_counts:
        for ip, count in sorted(failed_counts.items(), key=lambda x: -x[1]):
            print(f"  {ip:<16} {count} failed attempt(s)")
    else:
        print("  None found.")

    print(f"\nSuspicious IPs (more than {FAILED_ATTEMPTS_THRESHOLD} failed attempts):")
    suspicious_ips = {ip for ip, count in failed_counts.items() if count > FAILED_ATTEMPTS_THRESHOLD}
    if suspicious_ips:
        for ip in suspicious_ips:
            print(f"  {ip}  <-- possible brute-force attack")
    else:
        print("  None found.")

    print("\nSuccessful logins that came from a suspicious IP:")
    found_any = False
    for user, ip in successful_logins:
        if ip in suspicious_ips:
            print(f"  {ip} logged in as '{user}'  <-- INVESTIGATE, likely compromised")
            found_any = True
    if not found_any:
        print("  None found.")

    print("\n" + "=" * 50)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python simple_log_analyzer.py <path_to_log_file>")
        sys.exit(1)

    log_file = sys.argv[1]
    failed_counts, successful_logins = analyze_log(log_file)
    print_report(failed_counts, successful_logins)
