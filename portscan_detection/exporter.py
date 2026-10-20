"""Exporta a allowlist (fonte única da verdade) para formatos de cada SIEM."""
from __future__ import annotations

import csv
import io

from .allowlist import SOURCE_GROUPS


def _csv(header: list[str], rows: list[list]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return buf.getvalue()


def _source_entries(cfg: dict) -> list[dict]:
    return [e for g in SOURCE_GROUPS for e in (cfg.get(g) or [])]


def export_allowlist(cfg: dict, fmt: str) -> dict[str, str]:
    """Retorna {nome_do_arquivo: conteúdo}."""
    sources = _source_entries(cfg)
    exceptions = cfg.get("service_exceptions") or []
    if fmt == "splunk":
        return {
            "portscan_allowlist.csv": _csv(
                ["cidr", "name", "owner", "reason", "review_date"],
                [[e["cidr"], e.get("name", ""), e.get("owner", ""), e.get("reason", ""), e.get("review_date", "")]
                 for e in sources],
            ),
            "portscan_service_exceptions.csv": _csv(
                ["cidr", "port", "name", "owner", "reason", "review_date"],
                [[e["cidr"], p, e.get("name", ""), e.get("owner", ""), e.get("reason", ""), e.get("review_date", "")]
                 for e in exceptions for p in e["ports"]],
            ),
        }
    if fmt == "sentinel":
        return {
            "PortScanAllowlist.csv": _csv(
                ["SearchKey", "Name", "Owner", "Reason", "ReviewDate"],
                [[e["cidr"], e.get("name", ""), e.get("owner", ""), e.get("reason", ""), e.get("review_date", "")]
                 for e in sources],
            )
        }
    if fmt == "elastic":
        # Lista de valores (tipo ip_range) para usar em exceções das regras
        return {"portscan_allowlist_ip_range.txt": "\n".join(e["cidr"] for e in sources) + "\n"}
    raise ValueError(f"formato desconhecido: {fmt}")
