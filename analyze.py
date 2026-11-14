import re
import argparse
import json
from datetime import datetime

def parseLine(line):
    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
    user_match = re.search(r'for (\S+) from', line)

    try:
        timestamp = datetime.strptime("2026 " + line[:15], "%Y %b %d %H:%M:%S")
    except ValueError:
        return None

    if "Failed password" in line:
        if match:
            return ({
                "event": "FAILED",
                "ip": match.group(1),
                "user": user_match.group(1) if user_match else "unknown",
                "timestamp": timestamp,
            })
    elif "Accepted password" in line:
        if match:
            return ({
                "event": "ACCEPTED",
                "ip": match.group(1),
                "user": user_match.group(1) if user_match else "unknown",
                "timestamp": timestamp,
            })
    return None

def analyze_logs(lines, THRESHOLD, WINDOW = 60):
    ip_timestamps = {}
    max_window_attempts = {}
    compromises = []
    targeted_users = {}
    for l in lines:
        parsed = parseLine(l)
        if not parsed:
            continue
        ip = parsed["ip"]
        user = parsed["user"]
        timestamp = parsed["timestamp"]

        if parsed["event"] == "FAILED":
            if ip not in ip_timestamps:
                ip_timestamps[ip] = []
            ip_timestamps[ip].append(timestamp)

            ip_timestamps[ip] = [t for t in ip_timestamps[ip] if (timestamp - t).total_seconds() <= WINDOW]

            targeted_users[user] = targeted_users.get(user, 0) + 1

            current_count = len(ip_timestamps[ip])
            if current_count > max_window_attempts.get(ip, 0):
                max_window_attempts[ip] = current_count

        elif parsed["event"] == "ACCEPTED":
            recent_attempts = [
                t for t in ip_timestamps.get(ip, [])
                if (timestamp - t).total_seconds() <= WINDOW
            ]
            if len(recent_attempts) >= THRESHOLD:
                compromises.append({
                    "severity": "HIGH",
                    "type": "POSSIBLE COMPROMISE",
                    "mitre": "T1078 - Valid Accounts",
                    "ip": ip,
                    "user": user,
                    "attempts": len(recent_attempts),
                    "recommended_action": f"sudo ufw deny from {ip}",
                })
    suspicious_activity = []
    for ip, count in sorted(max_window_attempts.items(), key=lambda item: item[1], reverse=True):
        if count >= THRESHOLD:
            suspicious_activity.append({
                "severity": "MEDIUM",
                "type": "SUSPICIOUS ACTIVITY",
                "mitre": "T1110.001 - Password Guessing",
                "ip": ip,
                "failed_attempts": count,
                "recommended_action": f"sudo ufw deny from {ip}",
            })

    return compromises, suspicious_activity, targeted_users

def main():

    parser = argparse.ArgumentParser(description="SSH log analyzer")
    parser.add_argument("logfile", help="path to the log file")
    parser.add_argument("--threshold", type=int, default=5, help="attempt threshold")
    parser.add_argument("--output", default="report.json", help="report file")
    parser.add_argument("--window", type=int, default=60, help="time window in seconds")
    args = parser.parse_args()

    THRESHOLD = args.threshold
    WINDOW = args.window


    with open(args.logfile) as f:
        compromises, suspicious_activity, targeted_users = analyze_logs(f, THRESHOLD, WINDOW)
        report_data = {
            "summary": {
                "logfile": args.logfile,
                "compromises_count": len(compromises),
                "suspicious_ips_count": len(suspicious_activity),
            },
            "compromises": compromises,
            "suspicious_activity": suspicious_activity,
            "targeted_users": targeted_users,  # O TO NOWE!
        }
    with open(args.output, "w") as out:
        json.dump(report_data, out, indent=4)

    # Print Summary Window
    print("=== SSH ANALYSIS SUMMARY ===")
    print(f"Analyzed file: {args.logfile}")
    print(f"Detected possible breaches [HIGH]: {len(compromises)}")
    print(f"Suspicious IP addresses (Brute Force) [MEDIUM]: {len(suspicious_activity)}")
    print(f"Full report saved to: {args.output}")

if __name__ == "__main__":
    main()



