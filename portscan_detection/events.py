"""Leitura de eventos de conexão a partir de CSV normalizado."""
from __future__ import annotations

import csv
import ipaddress
from datetime import datetime, timezone

from .models import Event, normalize_action

REQUIRED_COLUMNS = ("timestamp", "src_ip", "dst_ip", "dst_port", "action")


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def load_events(path: str) -> tuple[list[Event], int]:
    """Retorna (eventos, linhas_inválidas). Linhas malformadas são contadas e ignoradas."""
    events: list[Event] = []
    bad = 0
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in REQUIRED_COLUMNS if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"CSV sem colunas obrigatórias: {', '.join(missing)}")
        for row in reader:
            try:
                src = str(ipaddress.ip_address(row["src_ip"].strip()))
                dst = str(ipaddress.ip_address(row["dst_ip"].strip()))
                port = int(row["dst_port"])
                if not 0 <= port <= 65535:
                    raise ValueError("porta fora do intervalo")
                events.append(
                    Event(parse_ts(row["timestamp"]), src, dst, port, normalize_action(row["action"]))
                )
            except (ValueError, KeyError, AttributeError):
                bad += 1
    return events, bad
