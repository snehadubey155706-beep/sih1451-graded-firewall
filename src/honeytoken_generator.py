import os
import json
import random
import string

HONEYTOKEN_DIR = "data/honeytokens"
REGISTRY_PATH = "data/honeytoken_registry.json"


def random_digits(n):
    return "".join(random.choice(string.digits) for _ in range(n))


def make_fake_card_number():
    """
    Generates a structurally valid (Luhn-passing) but entirely fake
    card number using a reserved test-number prefix. Never a real
    card BIN — this is purely a trackable decoy value.
    """
    prefix = "4000"  # reserved test-range prefix, not a real issuer BIN
    body = random_digits(11)
    partial = prefix + body

    def luhn_checksum(number):
        digits = [int(d) for d in number]
        odd = digits[-1::-2]
        even = digits[-2::-2]
        checksum = sum(odd)
        for d in even:
            checksum += sum(divmod(d * 2, 10))
        return checksum % 10

    check_digit = (10 - luhn_checksum(partial + "0")) % 10
    return partial + str(check_digit)


def make_fake_email():
    name = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
    return f"{name}@decoy-internal.local"


def generate_honeytokens():
    os.makedirs(HONEYTOKEN_DIR, exist_ok=True)
    registry = {"card_numbers": [], "emails": [], "api_keys": [], "files": []}

    # --- Fake card numbers (canary values) ---
    for _ in range(5):
        registry["card_numbers"].append(make_fake_card_number())

    # --- Fake emails/credentials ---
    for _ in range(5):
        registry["emails"].append(make_fake_email())

    # --- Fake API keys ---
    for _ in range(3):
        key = "sk_live_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(24))
        registry["api_keys"].append(key)

    # --- Fake decoy files ---
    passwords_file = os.path.join(HONEYTOKEN_DIR, "passwords.txt")
    with open(passwords_file, "w") as f:
        f.write("service,username,password\n")
        for i in range(5):
            f.write(f"admin_panel_{i},{registry['emails'][i % len(registry['emails'])]},P@ssw0rd_{random_digits(4)}\n")
    registry["files"].append(passwords_file)

    confidential_file = os.path.join(HONEYTOKEN_DIR, "confidential_report.txt")
    with open(confidential_file, "w") as f:
        f.write("INTERNAL USE ONLY\n\n")
        f.write("Q3 client card on file: " + registry["card_numbers"][0] + "\n")
        f.write("Escalation contact: " + registry["emails"][0] + "\n")
    registry["files"].append(confidential_file)

    employee_file = os.path.join(HONEYTOKEN_DIR, "employee_salary.csv")
    with open(employee_file, "w") as f:
        f.write("employee_id,name,salary,card_on_file\n")
        for i in range(5):
            f.write(f"E{100+i},Decoy Employee {i},{50000 + i*1000},{registry['card_numbers'][i % len(registry['card_numbers'])]}\n")
    registry["files"].append(employee_file)

    with open(REGISTRY_PATH, "w") as f:
        json.dump(registry, f, indent=2)

    print(f"Generated {len(registry['card_numbers'])} fake card numbers")
    print(f"Generated {len(registry['emails'])} fake emails")
    print(f"Generated {len(registry['api_keys'])} fake API keys")
    print(f"Generated {len(registry['files'])} decoy files in {HONEYTOKEN_DIR}/")
    print(f"Registry saved to {REGISTRY_PATH}")
    return registry


if __name__ == "__main__":
    generate_honeytokens()