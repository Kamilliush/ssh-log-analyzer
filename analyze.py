failed_attempts = 0

with open("auth.log") as f:
    for line in f:
        if "Failed password" in line:
            failed_attempts += 1
    print(failed_attempts)

