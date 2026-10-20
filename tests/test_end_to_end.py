"""Cenário completo: 4 scans reais escondidos no meio de tráfego normal e 4 fontes de falso positivo."""
from pathlib import Path

import pytest

from portscan_detection.allowlist import Allowlist
from portscan_detection.config import load_yaml, validate_thresholds
from portscan_detection.detector import PortScanDetector
from portscan_detection.events import load_events
from portscan_detection.exporter import export_allowlist
from portscan_detection.generator import generate_rows, write_csv

ROOT = Path(__file__).resolve().parent.parent

TRUE_POSITIVES = {"203.0.113.45", "10.20.1.77", "203.0.113.88", "192.0.2.99"}


@pytest.fixture(scope="module")
def events(tmp_path_factory):
    path = tmp_path_factory.mktemp("data") / "synthetic.csv"
    write_csv(str(path), generate_rows(seed=42, hours=8))
    loaded, bad = load_events(str(path))
    assert bad == 0
    return loaded


@pytest.fixture(scope="module")
def cfg():
    return validate_thresholds(load_yaml(str(ROOT / "config" / "thresholds.yml")))


@pytest.fixture(scope="module")
def allow_cfg():
    return load_yaml(str(ROOT / "config" / "allowlist.yml"))


def test_detects_exactly_the_true_positives(events, cfg, allow_cfg):
    detector = PortScanDetector(cfg, Allowlist(allow_cfg))
    alerts = detector.run(events)
    assert {a.src_ip for a in alerts} == TRUE_POSITIVES


def test_each_true_positive_uses_the_expected_profile(events, cfg, allow_cfg):
    alerts = PortScanDetector(cfg, Allowlist(allow_cfg)).run(events)
    by_src = {}
    for a in alerts:
        by_src.setdefault(a.src_ip, set()).add(a.profile)
    assert "ps001_vertical_fast" in by_src["203.0.113.45"]
    assert "ps002_horizontal_fast" in by_src["10.20.1.77"]
    assert "ps003_block_fast" in by_src["203.0.113.88"]
    assert by_src["192.0.2.99"] == {"ps004_vertical_slow"}  # lento demais para os perfis rápidos
    # scans rápidos não duplicam nos perfis lentos
    assert not any(name.startswith("ps004") for name in by_src["203.0.113.45"])
    assert not any(name.startswith("ps004") for name in by_src["10.20.1.77"])


def test_without_allowlist_known_noise_appears_but_ratio_still_protects(events, cfg, allow_cfg):
    structural = {"ignore_destination_cidrs": allow_cfg["ignore_destination_cidrs"]}
    detector = PortScanDetector(cfg, Allowlist(structural))
    sources = {a.src_ip for a in detector.run(events)}
    assert "10.10.50.5" in sources       # scanner de vulnerabilidades vira falso positivo
    assert "10.10.70.2" in sources       # health check do LB vira falso positivo
    assert "10.10.60.10" not in sources  # monitoramento: baixa taxa de falha já filtra
    assert "10.20.9.9" not in sources    # portas dinâmicas permitidas: taxa de falha filtra
    assert detector.stats["filtered_low_fail_ratio"] >= 2


def test_allowlist_export_formats(allow_cfg):
    splunk = export_allowlist(allow_cfg, "splunk")
    assert splunk["portscan_allowlist.csv"].startswith("cidr,name,owner,reason,review_date")
    assert "10.10.50.5/32" in splunk["portscan_allowlist.csv"]
    assert "10.10.70.2/32,443" in splunk["portscan_service_exceptions.csv"]
    assert "10.10.60.10/32" in export_allowlist(allow_cfg, "sentinel")["PortScanAllowlist.csv"]
    assert "10.10.50.5/32" in export_allowlist(allow_cfg, "elastic")["portscan_allowlist_ip_range.txt"]
    with pytest.raises(ValueError):
        export_allowlist(allow_cfg, "qradar")
