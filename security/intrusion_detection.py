import os

failed_attempts = {}

def detect_brute_force(username):
    if username not in failed_attempts:
        failed_attempts[username] = 1
    else:
        failed_attempts[username] += 1

    if failed_attempts[username] >= 3:
        log_attack(f"Brute force detected for {username}")
        return True
    return False


def log_attack(message):
    os.makedirs("monitoring", exist_ok=True)
    with open("monitoring/security_logs.txt", "a") as file:
        file.write(message + "\n")
