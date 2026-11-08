import re
THRESHOLD = 5
ip_attempts = {}

with open("auth.log") as f:
    for line in f:
        if "Failed password" in line:
            match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                ip_attempts[ip] = ip_attempts.get(ip, 0) + 1
    with open("report.txt", "w") as out:
        for ip, count in sorted(ip_attempts.items(), key=lambda item: item[1], reverse=True):
            if count >= THRESHOLD:
                out.write(f"SUSPICIOUS ACTIVITY:    IP: {ip} failed to connect {count} times\n")


