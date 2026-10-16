# Лабораторна робота №2. Консольні утиліти для задач кібербезпеки

**Варіант 8:** фільтр та аналізатор журналів DNS-запитів.

## Встановлення залежностей

З кореня репозиторію, в активованому віртуальному середовищі:

```
pip install -r requirements.txt
```

## Структура

```
labs/lab02/
├── __init__.py
├── main.py        # команди demo та analyze
├── task1.py       # Завдання 1: User, Admin, Session, AuditLog, UserAccount
├── task2.py       # Завдання 2: аналізатор DNS-журналів
├── README.md
└── data/
    └── data_v08/
        ├── dns_queries.csv   # журнал DNS-запитів (вхід)
        └── blacklist.txt     # чорний список доменів (вхід)
```

## Вхідні файли

- `dns_queries.csv` має колонки `Timestamp,ClientIP,Domain,QueryType`
  (час у форматі ISO 8601, наприклад `2026-09-27T08:00:01`).
- `blacklist.txt` містить по одному забороненому домену в рядку.

## Запуск

Демонстрація Завдання 1:

```
python -m labs.lab02.main demo
```

Аналіз DNS-журналу (Завдання 2). Файли за замовчуванням беруться з `data/data_v08`:

```
python -m labs.lab02.main analyze
```

З явними параметрами:

```
python -m labs.lab02.main analyze --dns-log labs/lab02/data/data_v08/dns_queries.csv --blacklist labs/lab02/data/data_v08/blacklist.txt --out-csv labs/lab02/data/data_v08/dns_alerts.csv --min-domain-len 60
```

## Параметри команди analyze

| Параметр | Опис | За замовчуванням |
|---|---|---|
| `--dns-log` | шлях до CSV-журналу DNS-запитів | `data/data_v08/dns_queries.csv` |
| `--blacklist` | шлях до файлу з чорним списком доменів | `data/data_v08/blacklist.txt` |
| `--out-csv` | шлях до CSV-файлу зі знайденими підозрілими запитами | `data/data_v08/dns_alerts.csv` |
| `--min-domain-len` | домен довший за це значення вважається підозрілим (додатне ціле) | `60` |

## Що перевіряє утиліта

- `BLACKMATCH` — домен (або його піддомен) є в чорному списку;
- `DGA-DETECT` — піддомен довший за 25 символів (регулярний вираз);
- `LONG-DOMAIN` — загальна довжина домену не менша за `--min-domain-len`;
- `SUSPICIOUS-TLD` — підозріла доменна зона (`.top`, `.xyz`, `.zip`, `.click`, `.tk`).

Також підраховується статистика запитів за типами (A, AAAA, TXT, MX) через `collections.Counter`.
Результат записується в CSV (колонки `Timestamp,ClientIP,Domain,QueryType,AlertKind,Reason`).
Попередження логуються у файл `dns_alerts.log` поруч із CSV-звітом.

## Поведінка при помилках

- Файл не знайдено: повідомлення `[ERROR]` і код завершення 1.
- Некоректний рядок у журналі (поганий час, IP чи домен): рядок пропускається, попередження записується в лог.
- Некоректний аргумент (наприклад, `--min-domain-len abc` або `0`): `argparse` виводить помилку і завершує програму з кодом 2.

## Перевірка якості коду

```
ruff check .
ruff format --check .
```