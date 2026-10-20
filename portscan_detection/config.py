"""Carregamento e validação dos arquivos de configuração (YAML)."""
from __future__ import annotations

import yaml

VALID_TYPES = {"vertical", "horizontal", "block"}
REQUIRED_KEYS = {
    "vertical": ("min_ports",),
    "horizontal": ("min_hosts",),
    "block": ("min_hosts", "min_ports"),
}


def load_yaml(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def validate_thresholds(cfg: dict) -> dict:
    profiles = cfg.get("profiles")
    if not profiles:
        raise ValueError("thresholds: nenhum perfil definido")
    seen: set[str] = set()
    for p in profiles:
        for key in ("name", "type", "window_seconds"):
            if key not in p:
                raise ValueError(f"perfil sem a chave obrigatória '{key}': {p}")
        if p["type"] not in VALID_TYPES:
            raise ValueError(f"tipo inválido '{p['type']}' no perfil {p['name']}")
        if p["name"] in seen:
            raise ValueError(f"perfil duplicado: {p['name']}")
        seen.add(p["name"])
        for key in REQUIRED_KEYS[p["type"]]:
            if key not in p:
                raise ValueError(f"perfil {p['name']} ({p['type']}) exige '{key}'")
        if p["window_seconds"] <= 0:
            raise ValueError(f"perfil {p['name']}: window_seconds deve ser > 0")
        ratio = p.get("min_fail_ratio", 0.0)
        if not 0.0 <= ratio <= 1.0:
            raise ValueError(f"perfil {p['name']}: min_fail_ratio deve estar entre 0 e 1")
    return cfg
