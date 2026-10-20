from datetime import datetime, timedelta

import pytest

from portscan_detection.allowlist import Allowlist
from portscan_detection.config import validate_thresholds
from portscan_detection.detector import PortScanDetector
from portscan_detection.models import Event, normalize_action

BASE = datetime(2026, 10, 19, 12, 0, 0)

CFG = {
    "cooldown_seconds": 900,
    "internal_networks": ["10.0.0.0/8"],
    "sensitive_ports": [22, 445, 3389],
    "profiles": [
        {"name": "vert", "type": "vertical", "window_seconds": 300, "min_ports": 20,
         "min_events": 20, "min_fail_ratio": 0.5},
        {"name": "horiz", "type": "horizontal", "window_seconds": 300, "min_hosts": 15,
         "min_events": 15, "min_fail_ratio": 0.5},
        {"name": "block", "type": "block", "window_seconds": 600, "min_hosts": 5,
         "min_ports": 10, "min_events": 30, "min_fail_ratio": 0.5},
    ],
}


def ev(sec, src, dst, port, action="blocked"):
    return Event(BASE + timedelta(seconds=sec), src, dst, port, action)


def vertical_events(src="203.0.113.5", n=30, action="blocked", dst="10.0.0.10"):
    return [ev(i, src, dst, 1000 + i, action) for i in range(n)]


def horizontal_events(src="10.1.1.1", n=20, port=445, action="blocked"):
    return [ev(i, src, f"10.2.0.{i + 1}", port, action) for i in range(n)]


def run(events, allow=None):
    det = PortScanDetector(CFG, Allowlist(allow or {}))
    return det, det.run(events)


def test_vertical_scan_detected():
    _, alerts = run(vertical_events())
    vert = [a for a in alerts if a.profile == "vert"]
    assert len(vert) >= 1
    assert vert[0].scan_type == "vertical"
    assert vert[0].target == "10.0.0.10"
    assert vert[0].distinct_ports >= 20


def test_below_threshold_no_alert():
    _, alerts = run(vertical_events(n=10))
    assert alerts == []


def test_window_expiry_resets_counting():
    first = [ev(i, "203.0.113.5", "10.0.0.10", 1000 + i) for i in range(12)]
    second = [ev(700 + i, "203.0.113.5", "10.0.0.10", 2000 + i) for i in range(12)]
    _, alerts = run(first + second)
    assert alerts == []


def test_allowed_traffic_is_not_a_scan():
    det, alerts = run(vertical_events(action="allowed"))
    assert alerts == []
    assert det.stats["filtered_low_fail_ratio"] >= 1


def test_allowlisted_source_suppressed():
    allow = {"authorized_scanners": [{"name": "nessus", "cidr": "203.0.113.5/32"}]}
    det, alerts = run(vertical_events(), allow)
    assert alerts == []
    assert det.stats["suppressed_allowlist"] == 30


def test_service_exception_only_for_listed_ports():
    allow = {"service_exceptions": [{"name": "lb", "cidr": "10.1.1.1/32", "ports": [443]}]}
    events = horizontal_events(src="10.1.1.1", port=443)
    _, alerts = run(events, allow)
    assert alerts == []
    # a mesma origem varrendo outra porta continua sendo detectada
    _, alerts = run(horizontal_events(src="10.1.1.1", port=445), allow)
    assert any(a.scan_type == "horizontal" for a in alerts)


def test_multicast_and_broadcast_ignored():
    allow = {"ignore_destination_cidrs": ["224.0.0.0/4", "255.255.255.255/32"]}
    events = [ev(i, "10.1.1.1", f"224.0.0.{i + 1}", 5353) for i in range(30)]
    det, alerts = run(events, allow)
    assert alerts == []
    assert det.stats["suppressed_ignored_destination"] == 30


def test_ongoing_scan_is_one_campaign_with_escalation_only():
    det, alerts = run(vertical_events(n=300))
    vert = [a for a in alerts if a.profile == "vert"]
    ranks = [{"low": 0, "medium": 1, "high": 2}[a.severity] for a in vert]
    assert 1 <= len(vert) <= 3
    assert ranks == sorted(set(ranks))  # só reemite quando a severidade sobe
    assert det.stats["deduplicated"] > 100


def test_campaign_rearms_after_silence():
    first = vertical_events(n=22)
    later = [ev(5000 + i, "203.0.113.5", "10.0.0.10", 3000 + i) for i in range(22)]
    _, alerts = run(first + later)
    assert len([a for a in alerts if a.profile == "vert"]) == 2


def test_horizontal_detection_and_internal_mapping():
    _, alerts = run(horizontal_events())
    horiz = [a for a in alerts if a.profile == "horiz"]
    assert len(horiz) == 1
    assert horiz[0].target == "*:445"
    assert horiz[0].src_scope == "interno"
    assert horiz[0].mitre == "T1046"
    assert 445 in horiz[0].sensitive_ports_hit


def test_external_scope_maps_to_active_scanning():
    _, alerts = run(vertical_events(src="203.0.113.5"))
    assert alerts[0].src_scope == "externo"
    assert alerts[0].mitre == "T1595.001"


def test_block_scan_detected():
    ports = list(range(100, 112))
    events = [ev(h * 12 + i, "203.0.113.9", f"10.0.1.{h}", p) for h in range(6) for i, p in enumerate(ports)]
    _, alerts = run(events)
    assert any(a.scan_type == "block" for a in alerts)


def test_slow_profile_requires_spread_over_hours_and_low_rate():
    cfg = dict(CFG)
    cfg["profiles"] = [{"name": "slow", "type": "vertical", "window_seconds": 21600, "min_ports": 40,
                        "min_events": 40, "min_fail_ratio": 0.7, "min_active_hours": 4,
                        "max_events_per_hour": 60}]
    fast = vertical_events(n=100)  # 100 portas em ~2 min: não é "slow"
    det = PortScanDetector(cfg, Allowlist({}))
    assert det.run(fast) == []
    slow = [ev(i * 360, "203.0.113.5", "10.0.0.10", 1000 + i) for i in range(50)]  # 1 porta a cada 6 min
    det = PortScanDetector(cfg, Allowlist({}))
    alerts = det.run(slow)
    assert len(alerts) == 1 and alerts[0].profile == "slow"


def test_normal_clients_do_not_alert():
    events = [ev(i * 10, "10.1.1.50", "10.0.0.10", 443, "allowed") for i in range(200)]
    _, alerts = run(events)
    assert alerts == []


def test_severity_scales_with_volume():
    _, small = run(vertical_events(n=22, src="203.0.113.6"))
    _, big = run(vertical_events(n=300, src="203.0.113.7"))
    order = {"low": 0, "medium": 1, "high": 2}
    assert order[big[0].severity] >= order[small[0].severity]


def test_expired_allowlist_entries_are_reported():
    allow = Allowlist(
        {"monitoring": [{"name": "velho", "cidr": "10.9.9.9/32", "review_date": "2020-01-01"}]},
        today=datetime(2026, 10, 19).date(),
    )
    assert allow.expired == ["velho"]


@pytest.mark.parametrize(
    "raw,expected",
    [("Deny", "blocked"), ("denied", "blocked"), ("DROP", "blocked"), ("reject", "blocked"),
     ("S0", "blocked"), ("REJ", "blocked"), ("allow", "allowed"), ("Accept", "allowed"),
     ("SF", "allowed"), ("", "other"), (None, "other"), ("alert", "other")],
)
def test_normalize_action(raw, expected):
    assert normalize_action(raw) == expected


def test_config_validation_errors():
    with pytest.raises(ValueError):
        validate_thresholds({})
    with pytest.raises(ValueError):
        validate_thresholds({"profiles": [{"name": "x", "type": "nope", "window_seconds": 60}]})
    with pytest.raises(ValueError):
        validate_thresholds({"profiles": [{"name": "x", "type": "vertical", "window_seconds": 60}]})
    with pytest.raises(ValueError):
        validate_thresholds({"profiles": [
            {"name": "x", "type": "vertical", "window_seconds": 60, "min_ports": 5, "min_fail_ratio": 2}]})
