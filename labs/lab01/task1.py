import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from shared.student import STUDENT_NAME, VARIANT_NUMBER


def analyze_passwords():
    print("--- Завдання 1: Аналіз паролів ---")
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")

    passwords = [
        "ThreatH@nt3r", "weak123", "P3n3trat10n@Test", "visitor",
        "Cyber@Defense2023", "normal", "Incident@R3sponse", "standard",
        "Risk@Analysis", "typical"
    ]

    criteria = {
        "min_length": 10,
        "require_digits": True,
        "require_upper": True,
        "require_special": True
    }

    forbidden = {
        "weak123", "visitor", "normal", "standard", "typical", "admin"
    }

    random_indices = [random.randint(0, len(passwords) - 1) for _ in range(3)]
    for idx in random_indices:
        passwords.append(passwords[idx])

    print(f"{'Пароль':<20} | {'Надійність':<15}")
    print("-" * 40)

    for pwd in passwords:
        if pwd in forbidden or len(pwd) < criteria["min_length"]:
            status = "Заборонений"
        else:
            has_upper = any(c.isupper() for c in pwd)
            has_digit = any(c.isdigit() for c in pwd)
            has_special = any(not c.isalnum() for c in pwd)

            met_criteria = sum([has_upper, has_digit, has_special])

            is_unique = passwords.count(pwd) == 1
            is_long_enough = len(pwd) >= (criteria["min_length"] + 4)

            if met_criteria == 3:
                if is_long_enough and is_unique:
                    status = "Дуже сильний"
                else:
                    status = "Сильний"
            elif met_criteria == 2:
                status = "Середній"
            else:
                status = "Слабкий"

        print(f"{pwd:<20} | {status:<15}")


if __name__ == "__main__":
    analyze_passwords()