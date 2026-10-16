"""Завдання 1: модель користувача, сесії та журналу аудиту."""

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import ClassVar

PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
EMAIL_PATTERN = re.compile(
    r"[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+"
)


def hash_password(password: str, salt: bytes) -> bytes:
    """Повертає хеш пароля з сіллю (PBKDF2-HMAC-SHA256)."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )


class User:
    """Користувач системи."""

    def __init__(
        self, username: str, email: str, role: str, active: bool = True
    ) -> None:
        self.username = username
        self.email = email
        self.role = role
        self.active = active
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError(f"Некоректний email: {value!r}")
        self._email = value

    def set_password(self, password: str) -> None:
        self.__password_salt = os.urandom(SALT_SIZE)
        self.__password_hash = hash_password(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        if not self.__password_hash:
            return False
        candidate = hash_password(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        status = "активний" if self.active else "неактивний"
        return f"User(username={self.username}, email={self.email}, role={self.role}, {status})"


class Admin(User):
    """Адміністратор: користувач із набором дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "admin",
        active: bool = True,
        permissions: set[str] | None = None,
    ) -> None:
        super().__init__(username, email, role, active)
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) or "немає"
        return f"{super().__str__()} | права: {perms}"


class Session:
    """Сеанс користувача."""

    def __init__(self, ip: str) -> None:
        now = datetime.now(timezone.utc)
        self.ip = ip
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        self.last_activity = datetime.now(timezone.utc)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        idle = datetime.now(timezone.utc) - self.last_activity
        return idle < timedelta(seconds=timeout_sec)


@dataclass
class AuditEntry:
    """Один запис журналу аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиту: список записів."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def add_log(self, username: str, action: str) -> None:
        self.entries.append(AuditEntry(datetime.now(timezone.utc), username, action))

    def show_all(self) -> None:
        for entry in self.entries:
            print(
                f"{entry.timestamp:%Y-%m-%d %H:%M:%S} UTC | {entry.username} | {entry.action}"
            )


SESSION_TIMEOUT_SEC = 900


class UserAccount:
    """Обліковий запис: користувач + сеанс + журнал аудиту (композиція)."""

    _ALLOWED_KEYS: ClassVar[dict[str, type]] = {
        "user": User,
        "session": Session,
        "audit_log": AuditLog,
    }

    def __init__(self, user: User, audit_log: AuditLog | None = None) -> None:
        self.user = user
        self.session: Session | None = None
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        ok = (
            self.user.active
            and username == self.user.username
            and self.user.check_password(password)
        )
        if not ok:
            self.audit_log.add_log(username, "login_failure")
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self.session is None:
            return
        self.session = None
        self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str):
        if key not in self._ALLOWED_KEYS:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(self, key: str, value) -> None:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(key)
        expected = self._ALLOWED_KEYS[key]
        allowed_none = key == "session" and value is None
        if not isinstance(value, expected) and not allowed_none:
            raise TypeError(f"Для ключа {key!r} очікується {expected.__name__}")
        setattr(self, key, value)
