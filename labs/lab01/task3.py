"""
Модуль для виконання Завдання 3: Хешування, CSV-база та JSON-логування.
"""
import csv
import datetime
import functools
import hashlib
import json
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from shared.student import STUDENT_NAME, VARIANT_NUMBER

# Персональна сіль (доповнена нулями до 5 символів)
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}"
MIN_PASSWORD_LENGTH = 11


class ValidationError(Exception):
    """Власний виняток для помилок валідації довжини пароля."""


def log_event(func):
    """Декоратор для логування спроб входу у JSON файл."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")

        try:
            result = func(*args, **kwargs)
            status = "success" if result else "failure"
        except Exception:
            status = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": status,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "args": [username, "***"],  # Приховуємо пароль у логах
                "kwargs": kwargs
            }

            data_dir = os.path.join(os.path.dirname(__file__), "data")
            os.makedirs(data_dir, exist_ok=True)
            log_path = os.path.join(data_dir, "log.json")

            logs = []
            if os.path.exists(log_path):
                try:
                    with open(log_path, "r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass

            logs.append(log_entry)

            try:
                with open(log_path, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except (OSError, PermissionError) as e:
                print(f"Помилка запису логу: {e}")

        return result

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    """Генерує sha256 хеш пароля із сіллю."""
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Довжина пароля менша за {MIN_PASSWORD_LENGTH} символів.")

    combined = password + salt
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()


def create_user(username, password):
    """Створює запис користувача з хешованим паролем."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list):
    """Створює CSV базу даних користувачів."""
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)
    csv_path = os.path.join(data_dir, "users.csv")

    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["login", "hash_password"])
            for username, password in users_list:
                try:
                    user_record = create_user(username, password)
                    writer.writerow(user_record)
                except (ValueError, ValidationError) as e:
                    print(f"Пропуск користувача {username}: {e}")
        print("Базу даних успішно створено.\n")
    except (OSError, PermissionError) as e:
        print(f"Помилка створення бази даних: {e}")


@log_event
def login(username: str, password: str, users_db: list) -> bool:
    """Перевіряє облікові дані користувача."""
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми.")

    for row in users_db:
        if len(row) == 2:
            db_user, db_hash = row
            if db_user == username:
                try:
                    current_hash = generate_hash(password, PERSONAL_SALT)
                    return current_hash == db_hash
                except ValidationError:
                    return False
    return False


def main():
    """Головна функція для тестування роботи модуля."""
    print("--- Завдання 3: Хешування та логування ---")
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")

    users_to_register = (
        ("admin", "SuperSecurePass123"),
        ("yaryna", "MyStr0ngP@ssw0rd!"),
        ("user1", "Password2026!!!"),
        ("hacker", "short"),
        ("test_acc", "Testing1234567"),
        ("manager", "ManagerP@ss2026"),
        ("guest", "GuestAccount123"),
        ("developer", "DevEnvP@ssword"),
        ("analyst", "DataAnalysis2026"),
        ("ceo", "ChiefExecPass!")
    )

    create_users(users_to_register)

    users_db = []
    csv_path = os.path.join(os.path.dirname(__file__), "data", "users.csv")

    print("Читання бази даних:")
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader)
            print(f"{header[0]:<15} | {header[1]}")
            print("-" * 80)
            for row in reader:
                users_db.append(row)
                print(f"{row[0]:<15} | {row[1]}")
    except FileNotFoundError as e:
        print(f"Файл бази даних не знайдено: {e}")
        return

    print("\nТестування авторизації:")
    try:
        is_logged_in = login("yaryna", "MyStr0ngP@ssw0rd!", users_db)
        print(f"Вхід для yaryna: {'УСПІШНО' if is_logged_in else 'ВІДМОВЛЕНО'}")

        is_logged_in = login("admin", "WrongPassword", users_db)
        print(f"Вхід для admin (невірний пароль): {'УСПІШНО' if is_logged_in else 'ВІДМОВЛЕНО'}")

        login("", "password", users_db)
    except ValueError as e:
        print(f"Перехоплено ValueError: {e}")
    except Exception as e:  # noqa: BLE001
        print(f"Перехоплено невідому помилку: {e}")


if __name__ == "__main__":
    main()