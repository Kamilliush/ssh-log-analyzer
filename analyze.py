import re
THRESHOLD = 5
ip_attempts = {}

with open("auth_compromise.log") as f:
    with open("report.txt", "w") as out:
        for line in f:
                if "Failed password" in line:
                    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                    if match:
                        ip = match.group(1)
                        ip_attempts[ip] = ip_attempts.get(ip, 0) + 1

                if "Accepted password" in line:
                    match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
                    login = re.search(r'for (\S+) from', line)
                    if match:
                        ip = match.group(1)
                        if ip in ip_attempts:
                            if ip_attempts[ip] >= THRESHOLD:
                                out.write(f'POSSIBLE COMPROMISE: {ip} logged in as \'{login.group(1)}\' after {ip_attempts[ip]} attempts\n')

        out.write("\n")
        for ip, count in sorted(ip_attempts.items(), key=lambda item: item[1], reverse=True):
            if count >= THRESHOLD:
                out.write(f"SUSPICIOUS ACTIVITY: {ip} failed to connect {count} times\n")














# with open("auth.log") as f:
#     for line in f:
#         if "Failed password" in line:
#             match = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
#             if match:
#                 ip = match.group(1)
#                 ip_attempts[ip] = ip_attempts.get(ip, 0) + 1
#     with open("report.txt", "w") as out:
#         for ip, count in sorted(ip_attempts.items(), key=lambda item: item[1], reverse=True):
#             if count >= THRESHOLD:
#                 out.write(f"SUSPICIOUS ACTIVITY:    IP: {ip} failed to connect {count} times\n")


