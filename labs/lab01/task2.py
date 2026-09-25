import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, VARIANT_NUMBER


def check_access():
    print("--- Завдання 2: Система контролю доступу ---")
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")

    users = {
        "crypto_specialist": {"role": "cryptographer", "clearance": 4, "department": "Cryptography", "active": True},
        "privacy_officer": {"role": "privacy_analyst", "clearance": 3, "department": "Privacy", "active": True},
        "data_scientist": {"role": "data_analyst", "clearance": 2, "department": "Analytics", "active": True},
        "field_engineer": {"role": "field_support", "clearance": 2, "department": "Field Ops", "active": True},
        "test_account": {"role": "testing", "clearance": 1, "department": "QA", "active": False}
    }

    resources = [
        ("encryption_keys", 4), ("privacy_policies", 3), ("anonymized_data", 2),
        ("field_reports", 2), ("crypto_algorithms", 4), ("consent_forms", 1),
        ("data_classification", 3), ("key_management", 4), ("statistical_models", 2),
        ("public_datasets", 1)
    ]

    security_levels = ("Unclassified", "For Official Use", "Confidential", "Secret")
    blocked_users = {"test_account", "gdpr_violation", "data_breach_user"}

    print("Доступні ресурси системи:")
    for res_name, res_level in resources:
        level_name = security_levels[res_level - 1]
        print(f"- {res_name}: {level_name}")

    print("\nРезультати перевірки доступу:")

    users_to_check = list(users.keys()) + ["gdpr_violation", "unknown_hacker"]

    for username in users_to_check:
        for res_name, res_level in resources:
            if username not in users:
                result = "DENY (User not found)"
            elif username in blocked_users:
                result = "DENY (User is blocked)"
            elif not users[username].get("active"):
                result = "DENY (Account inactive)"
            elif users[username].get("clearance", 0) >= res_level:
                result = "ALLOW"
            else:
                result = "DENY (Insufficient clearance)"

            print(f"user={username} resource={res_name} -> {result}")


if __name__ == "__main__":
    check_access()