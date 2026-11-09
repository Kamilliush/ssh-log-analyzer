import re
import argparse

parser = argparse.ArgumentParser(description="SSH log analyzer")
parser.add_argument("logfile", help="path to the log file")
parser.add_argument("--threshold", type=int, default=5, help="attempt threshold")
parser.add_argument("--output", default="report.txt", help="report file")
args = parser.parse_args()

THRESHOLD = args.threshold
ip_attempts = {}
compromises = []

with open(args.logfile) as f:
    for line in f:

        if "Failed password" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

        elif "Accepted password" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            login = re.search(r'for (\S+) from', line)
            if match:
                ip = match.group(1)
                if ip in ip_attempts:
                    if ip_attempts[ip] >= THRESHOLD:
                        compromises.append(
                            f"[HIGH] POSSIBLE COMPROMISE [MITRE: T1078 - Valid Accounts]: {ip} logged in as '{login.group(1)}' after {ip_attempts[ip]} attempts | Recommended action: sudo ufw deny from {ip}\n"
                        )

    with open(args.output, "w") as out:
        for alert in compromises:
            out.write(alert)

        out.write("\n")

        for ip, count in sorted(ip_attempts.items(), key=lambda item: item[1], reverse=True):
            if count >= THRESHOLD:
                out.write(
                    f"[MEDIUM] SUSPICIOUS ACTIVITY [MITRE: T1110.001 - Password Guessing]: {ip} failed to connect {count} times | Recommended action: sudo ufw deny from {ip}\n"
                )
suspicious_ips_count = 0
for ip, count in ip_attempts.items():
    if count >= THRESHOLD:
        suspicious_ips_count += 1

print("=== SSH ANALYSIS SUMMARY ===")
print(f"Analyzed file: {args.logfile}")
print(f"Detected possible breaches [HIGH]: {len(compromises)}")
print(f"Suspicious IP addresses (Brute Force) [MEDIUM]: {suspicious_ips_count}")
print(f"Full report saved to: {args.output}")