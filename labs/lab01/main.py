import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from task1 import analyze_passwords
from task2 import check_access
from task3 import main as task3_main


def main():
    print("=" * 60)
    print("      ЗАПУСК УСІХ ЗАВДАНЬ ЛАБОРАТОРНОЇ РОБОТИ №1")
    print("=" * 60 + "\n")

    analyze_passwords()

    print("\n" + "=" * 60 + "\n")

    check_access()

    print("\n" + "=" * 60 + "\n")

    task3_main()

    print("\n" + "=" * 60)
    print("      ВИКОНАННЯ ЛАБОРАТОРНОЇ РОБОТИ ЗАВЕРШЕНО")
    print("=" * 60)


if __name__ == "__main__":
    main()
