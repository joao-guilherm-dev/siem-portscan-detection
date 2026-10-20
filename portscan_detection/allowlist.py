"""Allowlist com governança: dono, motivo e data de revisão por entrada."""
from __future__ import annotations

import ipaddress
import logging
from datetime import date
from functools import lru_cache

log = logging.getLogger("portscan")

SOURCE_GROUPS = ("authorized_scanners", "monitoring", "health_checks")


@lru_cache(maxsize=65536)
def _ip(value: str):
    return ipaddress.ip_address(value)


def _as_date(value) -> date:
    return value if isinstance(value, date) else date.fromisoformat(str(value))


class Allowlist:
    def __init__(self, cfg: dict | None = None, today: date | None = None):
        cfg = cfg or {}
        today = today or date.today()
        self._sources: list[tuple] = []
        self._port_exceptions: list[tuple] = []
        self.expired: list[str] = []
        self._ignored_dst = [
            ipaddress.ip_network(c, strict=False) for c in cfg.get("ignore_destination_cidrs", []) or []
        ]
        for group in SOURCE_GROUPS:
            for entry in cfg.get(group, []) or []:
                name = entry.get("name", entry["cidr"])
                self._sources.append((ipaddress.ip_network(entry["cidr"], strict=False), name))
                self._check_review(entry, name, today)
        for entry in cfg.get("service_exceptions", []) or []:
            name = entry.get("name", entry["cidr"])
            ports = frozenset(int(p) for p in entry["ports"])
            self._port_exceptions.append((ipaddress.ip_network(entry["cidr"], strict=False), ports, name))
            self._check_review(entry, name, today)

    def _check_review(self, entry: dict, name: str, today: date) -> None:
        review = entry.get("review_date")
        if review and _as_date(review) < today:
            self.expired.append(name)
            log.warning("Entrada da allowlist com revisão vencida: %s (%s)", name, review)

    def source_name(self, ip: str) -> str | None:
        addr = _ip(ip)
        for net, name in self._sources:
            if addr in net:
                return name
        return None

    def port_exception(self, ip: str, port: int) -> str | None:
        addr = _ip(ip)
        for net, ports, name in self._port_exceptions:
            if port in ports and addr in net:
                return name
        return None

    def ignores_destination(self, ip: str) -> bool:
        addr = _ip(ip)
        return any(addr in net for net in self._ignored_dst)
