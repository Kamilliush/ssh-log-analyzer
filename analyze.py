import re
import argparse
import json

parser = argparse.ArgumentParser(description="SSH log analyzer")
parser.add_argument("logfile", help="path to the log file")
parser.add_argument("--threshold", type=int, default=5, help="attempt threshold")
parser.add_argument("--output", default="report.json", help="report file")
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
                        compromises.append({
                            "severity": "HIGH",
                            "type": "POSSIBLE COMPROMISE",
                            "mitre": "T1078 - Valid Accounts",
                            "ip": ip,
                            "user": login.group(1),
                            "attempts": ip_attempts[ip],
                            "recommended_action": f"sudo ufw deny from {ip}",
                        })

        suspicious_activity = []
        for ip, count in sorted(
                ip_attempts.items(), key=lambda item: item[1], reverse=True
        ):
            if count >= THRESHOLD:
                suspicious_activity.append({
                    "severity": "MEDIUM",
                    "type": "SUSPICIOUS ACTIVITY",
                    "mitre": "T1110.001 - Password Guessing",
                    "ip": ip,
                    "failed_attempts": count,
                    "recommended_action": f"sudo ufw deny from {ip}",
                })
        report_data = {
            "summary": {
                "logfile": args.logfile,
                "compromises_count": len(compromises),
                "suspicious_ips_count": len(suspicious_activity),
            },
            "compromises": compromises,
            "suspicious_activity": suspicious_activity,
        }
with open(args.output, "w") as out:
    json.dump(report_data, out, indent=4)



#Print Summary Window

print("=== SSH ANALYSIS SUMMARY ===")
print(f"Analyzed file: {args.logfile}")
print(f"Detected possible breaches [HIGH]: {len(compromises)}")
print(f"Suspicious IP addresses (Brute Force) [MEDIUM]: {len(suspicious_activity)}")
print(f"Full report saved to: {args.output}")


