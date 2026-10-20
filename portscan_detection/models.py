"""Modelos de dados e normalização de ações de firewall."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime

# Estados do Zeek (conn_state) e ações de firewalls que indicam conexão não concluída.
BLOCKED_EXACT = {"s0", "rej", "rstos0", "sh", "rst"}
BLOCKED_PREFIX = ("block", "den", "drop", "reject", "reset", "fail", "refus")
ALLOWED_EXACT = {"sf"}
ALLOWED_PREFIX = ("allow", "accept", "permit", "success", "establish")


def normalize_action(raw: str | None) -> str:
    """Converte a ação bruta do log em 'blocked', 'allowed' ou 'other'."""
    value = (raw or "").strip().lower()
    if value in BLOCKED_EXACT or value.startswith(BLOCKED_PREFIX):
        return "blocked"
    if value in ALLOWED_EXACT or value.startswith(ALLOWED_PREFIX):
        return "allowed"
    return "other"


@dataclass(frozen=True)
class Event:
    ts: datetime
    src: str
    dst: str
    port: int
    action: str  # blocked | allowed | other


@dataclass
class Alert:
    profile: str
    scan_type: str
    src_ip: str
    src_scope: str
    target: str
    first_seen: str
    last_seen: str
    events: int
    distinct_ports: int
    distinct_hosts: int
    fail_ratio: float
    severity: str
    mitre: str
    sensitive_ports_hit: list = field(default_factory=list)
    sample_ports: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
