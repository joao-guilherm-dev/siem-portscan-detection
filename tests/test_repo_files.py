"""Validação estática dos artefatos de detecção (roda no CI)."""
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
QUERY_FILES = sorted(p for ext in ("spl", "kql", "esql") for p in (ROOT / "queries").rglob(f"*.{ext}"))


def test_query_files_exist():
    assert len(QUERY_FILES) >= 15


@pytest.mark.parametrize("path", QUERY_FILES, ids=lambda p: p.name)
def test_query_has_id_and_mitre_header(path):
    text = path.read_text(encoding="utf-8")
    head = text[:600]
    assert "PS-00" in head, "cabeçalho deve conter o ID da detecção (PS-00x)"
    assert "T1046" in head or "T1595" in head, "cabeçalho deve conter o mapeamento MITRE"
    assert len(text.splitlines()) >= 5


@pytest.mark.parametrize("path", [p for p in QUERY_FILES if p.suffix in (".spl", ".kql", ".esql") and "ps-00" in p.name
                                  and not any(x in p.name for x in ("ps-005", "ps-006"))],
                         ids=lambda p: p.name)
def test_core_queries_have_false_positive_layers(path):
    text = path.read_text(encoding="utf-8").lower()
    assert "224.0.0.0/4" in text, "descarte estrutural (multicast) ausente"
    assert "0.5" in text or "0.7" in text, "limiar de taxa de falha/bloqueio ausente"


def test_sigma_documents_are_valid_and_correlated():
    docs = list(yaml.safe_load_all((ROOT / "queries/sigma/portscan_correlation.yml").read_text(encoding="utf-8")))
    assert len(docs) == 3
    base_names = {d["name"] for d in docs if "name" in d}
    for d in docs:
        assert {"title", "id", "logsource" if "correlation" not in d else "correlation"} <= d.keys()
        if "correlation" in d:
            assert d["correlation"]["type"] == "value_count"
            assert set(d["correlation"]["rules"]) <= base_names
    ids = [d["id"] for d in docs]
    assert len(ids) == len(set(ids))


def test_sentinel_rule_yaml_is_valid():
    rule = yaml.safe_load((ROOT / "queries/sentinel/ps-001-analytic-rule.yaml").read_text(encoding="utf-8"))
    for key in ("id", "name", "severity", "query", "tactics", "relevantTechniques", "kind"):
        assert key in rule
    assert rule["kind"] == "Scheduled"


def test_elastic_rule_json_is_valid():
    rule = json.loads((ROOT / "queries/elastic/ps-001-threshold-rule.json").read_text(encoding="utf-8"))
    assert rule["type"] == "threshold"
    assert rule["threshold"]["cardinality"][0]["field"] == "destination.port"
    assert rule["threat"][0]["technique"][0]["id"] == "T1046"
    assert rule["false_positives"], "a regra deve documentar falsos positivos conhecidos"


def test_thresholds_in_queries_match_config():
    """Garante que os limiares-padrão das queries não divergem do config/thresholds.yml."""
    cfg = yaml.safe_load((ROOT / "config/thresholds.yml").read_text(encoding="utf-8"))
    prof = {p["name"]: p for p in cfg["profiles"]}
    spl = (ROOT / "queries/splunk/ps-001-vertical-scan.spl").read_text(encoding="utf-8")
    assert f"distinct_ports>={prof['ps001_vertical_fast']['min_ports']}" in spl
    spl2 = (ROOT / "queries/splunk/ps-002-horizontal-scan.spl").read_text(encoding="utf-8")
    assert f"distinct_hosts>={prof['ps002_horizontal_fast']['min_hosts']}" in spl2
    kql3 = (ROOT / "queries/sentinel/ps-003-block-scan.kql").read_text(encoding="utf-8")
    p3 = prof["ps003_block_fast"]
    assert f"DistinctHosts >= {p3['min_hosts']}" in kql3 and f"DistinctPorts >= {p3['min_ports']}" in kql3
    esql4 = (ROOT / "queries/elastic/ps-004-slow-scan.esql").read_text(encoding="utf-8")
    assert f"distinct_ports >= {prof['ps004_vertical_slow']['min_ports']}" in esql4
