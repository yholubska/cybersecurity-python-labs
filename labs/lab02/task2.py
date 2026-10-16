"""Завдання 2 (варіант 8): аналізатор журналів DNS-запитів."""

import csv
import logging
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("dns_analyzer")

SUSPICIOUS_TLDS = {"top", "xyz", "zip", "click", "tk"}
LONG_LABEL_PATTERN = re.compile(r"(?:^|\.)[^.]{25,}(?=\.)")
IPV4_PATTERN = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
DOMAIN_PATTERN = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+")
QUERY_TYPES = ("A", "AAAA", "TXT", "MX")


@dataclass
class DnsRecord:
    """Один DNS-запит із журналу."""

    timestamp: datetime
    client_ip: str
    domain: str
    query_type: str


@dataclass
class Alert:
    """Підозрілий запит і причина, чому його позначено."""

    kind: str
    record: DnsRecord
    reason: str


def load_blacklist(path: Path) -> set[str]:
    """Читає чорний список доменів: по одному в рядку."""
    with path.open(encoding="utf-8") as file:
        return {line.strip().lower() for line in file if line.strip()}


def read_dns_log(path: Path) -> Iterator[DnsRecord]:
    """Читає CSV-журнал по одному рядку (генератор) і пропускає зіпсовані."""
    with path.open(encoding="utf-8", newline="") as file:
        for number, row in enumerate(csv.DictReader(file), start=2):
            try:
                record = DnsRecord(
                    timestamp=datetime.fromisoformat(row["Timestamp"]),
                    client_ip=row["ClientIP"].strip(),
                    domain=row["Domain"].strip().lower(),
                    query_type=row["QueryType"].strip().upper(),
                )
            except (KeyError, ValueError, AttributeError):
                logger.warning("Рядок %d пропущено: некоректні дані", number)
                continue
            ip_ok = IPV4_PATTERN.fullmatch(record.client_ip)
            domain_ok = DOMAIN_PATTERN.fullmatch(record.domain)
            if not ip_ok or not domain_ok:
                logger.warning("Рядок %d пропущено: некоректний IP або домен", number)
                continue
            yield record


def check_record(
    record: DnsRecord, blacklist: set[str], min_domain_len: int
) -> list[Alert]:
    """Перевіряє один запит і повертає список знайдених підозр."""
    alerts: list[Alert] = []
    domain = record.domain
    if domain in blacklist or any(domain.endswith("." + item) for item in blacklist):
        alerts.append(Alert("BLACKMATCH", record, "домен у чорному списку"))
    if LONG_LABEL_PATTERN.search(domain):
        alerts.append(
            Alert("DGA-DETECT", record, "надто довгий піддомен (25+ символів)")
        )
    if len(domain) >= min_domain_len:
        alerts.append(
            Alert(
                "LONG-DOMAIN",
                record,
                f"довжина домену {len(domain)} >= {min_domain_len}",
            )
        )
    tld = domain.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        alerts.append(Alert("SUSPICIOUS-TLD", record, f"підозрілий TLD .{tld}"))
    return alerts


def analyze(
    dns_log: Path, blacklist: set[str], min_domain_len: int
) -> tuple[int, Counter, list[Alert]]:
    """Проходить журнал і повертає: кількість запитів, статистику типів, підозри."""
    total = 0
    stats: Counter = Counter()
    alerts: list[Alert] = []
    for record in read_dns_log(dns_log):
        total += 1
        stats[record.query_type] += 1
        found = check_record(record, blacklist, min_domain_len)
        for alert in found:
            logger.warning("%s: %s -> %s", alert.kind, record.client_ip, record.domain)
        alerts.extend(found)
    return total, stats, alerts


def write_alerts_csv(alerts: list[Alert], path: Path) -> None:
    """Записує підозрілі запити у CSV-файл."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["Timestamp", "ClientIP", "Domain", "QueryType", "AlertKind", "Reason"]
        )
        for alert in alerts:
            rec = alert.record
            writer.writerow(
                [
                    rec.timestamp.isoformat(),
                    rec.client_ip,
                    rec.domain,
                    rec.query_type,
                    alert.kind,
                    alert.reason,
                ]
            )


def configure_logging(log_file: Path) -> None:
    """Налаштовує логування: INFO у консоль, попередження у файл."""
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.addFilter(lambda record: record.levelno == logging.INFO)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(console)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    to_file = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    to_file.setLevel(logging.WARNING)
    to_file.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(to_file)


def run_analyze(
    dns_log: Path, blacklist_path: Path, out_csv: Path, min_domain_len: int
) -> int:
    """Запускає аналіз і друкує звіт. Повертає код завершення (0 — успіх)."""
    configure_logging(out_csv.with_suffix(".log"))
    try:
        blacklist = load_blacklist(blacklist_path)
        logger.info("Parsing DNS log file %s...", dns_log)
        total, stats, alerts = analyze(dns_log, blacklist, min_domain_len)
    except FileNotFoundError as error:
        print(f"[ERROR] Файл не знайдено: {error.filename}")
        return 1
    except OSError as error:
        print(f"[ERROR] Не вдалося прочитати файл: {error}")
        return 1

    logger.info("Processed %d DNS query records.", total)
    print("\n=== Query Type Breakdown ===")
    for qtype in QUERY_TYPES:
        count = stats.get(qtype, 0)
        percent = count / total * 100 if total else 0.0
        print(f"{qtype:<5}: {count} ({percent:.1f}%)")

    print("\n=== Suspicious DNS Activity ===")
    for alert in alerts:
        rec = alert.record
        print(
            f"[{alert.kind}] Client {rec.client_ip} queried {rec.domain} "
            f"({rec.query_type}): {alert.reason}"
        )
    if not alerts:
        print("Підозрілих запитів не знайдено.")

    write_alerts_csv(alerts, out_csv)
    print()
    logger.info("Suspicious records exported to %s", out_csv)
    return 0
