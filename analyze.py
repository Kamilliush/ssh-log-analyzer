with open("auth.log") as f:
    lines = f.readlines()
    failed_attemps = 0
    for line in lines:
        if "Failed password" in line:
            failed_attemps += 1
print(failed_attemps)

