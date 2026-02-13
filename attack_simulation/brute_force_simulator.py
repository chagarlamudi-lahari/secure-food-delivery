from security.intrusion_detection import detect_brute_force, log_attack

def simulate_attack(username):
    print("Starting brute force simulation...\n")

    for i in range(5):
        print(f"Attempt {i+1}")

        if detect_brute_force(username):
            print("Account blocked due to suspicious activity!")
            log_attack(f"[SIMULATION] Account blocked for {username}")
            break
        else:
            log_attack(f"[SIMULATION] Failed attempt {i+1} for {username}")

    print("\nSimulation completed.")

# Run simulation
simulate_attack("demo_user")
