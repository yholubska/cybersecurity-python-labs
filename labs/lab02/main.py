"""Точка входу лабораторної роботи №2: команди demo та analyze."""

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from labs.lab02.task1 import SESSION_TIMEOUT_SEC, Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import run_analyze

DATA_DIR = Path(__file__).parent / "data" / "data_v08"


def run_demo() -> None:
    """Демонстрація Завдання 1."""
    print("=== 1. Створення користувача ===")
    user = User("yarina_k", "yarina_k@example.com", "student")
    user.set_password("Str0ng_Pass!")
    print(user)
    account = UserAccount(user, AuditLog())

    print("\n=== 2. Невдалий вхід (неправильний пароль) ===")
    print("Вхід виконано:", account.login("yarina_k", "wrong_password", "192.168.0.10"))
    print("Автентифікований:", account.is_authenticated())

    print("\n=== 3. Успішний вхід ===")
    print("Вхід виконано:", account.login("yarina_k", "Str0ng_Pass!", "192.168.0.10"))
    print("Автентифікований:", account.is_authenticated())

    print("\n=== 4. Зміна email із перевіркою ===")
    user.email = "new_mail@example.com"
    print("Новий email:", user.email)
    try:
        user.email = "1bad@mail"
    except ValueError as error:
        print("Помилка:", error)

    print("\n=== 5. Права адміністратора ===")
    admin = Admin("admin_one", "admin_one@example.com")
    admin.grant_permission("read_logs")
    admin.grant_permission("block_ip")
    print(admin)
    admin.revoke_permission("block_ip")
    print("Є право block_ip:", admin.has_permission("block_ip"))
    print(admin)

    print("\n=== 6. Завершення сеансу за таймаутом ===")
    old_time = datetime.now(timezone.utc) - timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    account["session"].last_activity = old_time
    print("Автентифікований:", account.is_authenticated())

    print("\n=== 7. Новий вхід і вихід із системи ===")
    account.login("yarina_k", "Str0ng_Pass!", "192.168.0.10")
    account.logout()
    print("Автентифікований:", account.is_authenticated())

    print("\n=== 8. Журнал аудиту ===")
    account.audit_log.show_all()


def positive_int(value: str) -> int:
    """Перевіряє, що аргумент є додатним цілим числом."""
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} не є цілим числом") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("значення має бути додатним числом")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Лабораторна робота №2")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="демонстрація Завдання 1")
    analyze = subparsers.add_parser("analyze", help="аналіз DNS-журналу (Завдання 2)")
    analyze.add_argument("--dns-log", type=Path, default=DATA_DIR / "dns_queries.csv")
    analyze.add_argument("--blacklist", type=Path, default=DATA_DIR / "blacklist.txt")
    analyze.add_argument("--out-csv", type=Path, default=DATA_DIR / "dns_alerts.csv")
    analyze.add_argument("--min-domain-len", type=positive_int, default=60)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        code = run_analyze(
            args.dns_log, args.blacklist, args.out_csv, args.min_domain_len
        )
        sys.exit(code)


if __name__ == "__main__":
    main()
