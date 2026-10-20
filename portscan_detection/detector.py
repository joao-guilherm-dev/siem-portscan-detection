"""Motor de detecção de port scan (janela deslizante, contadores incrementais).

Perfis suportados:
  vertical   -> uma origem, um destino, muitas portas distintas
  horizontal -> uma origem, uma porta, muitos hosts distintos
  block      -> uma origem, muitos hosts E muitas portas

Camadas anti-falso-positivo: allowlist, exceções por serviço, destinos ignorados
(multicast/broadcast), taxa mínima de falha, mínimo de eventos e deduplicação por
campanha (um alerta por scan, com reemissão apenas em escalada de severidade).
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict, deque
from datetime import timedelta

from .allowlist import Allowlist
from .models import Alert, Event


def _dec(counter: Counter, key) -> None:
    counter[key] -= 1
    if counter[key] <= 0:
        del counter[key]


def _dec_nested(outer: dict, k1, k2) -> None:
    inner = outer[k1]
    _dec(inner, k2)
    if not inner:
        del outer[k1]


class _Window:
    """Estado incremental da janela de uma origem (evita recalcular tudo a cada evento)."""

    def __init__(self) -> None:
        self.dq: deque[Event] = deque()
        self.ports_by_dst: dict[str, Counter] = defaultdict(Counter)
        self.hosts_by_port: dict[int, Counter] = defaultdict(Counter)
        self.dst_events: Counter = Counter()
        self.dst_blocked: Counter = Counter()
        self.port_events: Counter = Counter()
        self.port_blocked: Counter = Counter()
        self.ports_all: Counter = Counter()
        self.hosts_all: Counter = Counter()
        self.blocked = 0
        self.hours: Counter = Counter()  # horas ativas na janela (para perfis lentos)

    def add(self, e: Event) -> None:
        self.dq.append(e)
        self.ports_by_dst[e.dst][e.port] += 1
        self.hosts_by_port[e.port][e.dst] += 1
        self.dst_events[e.dst] += 1
        self.port_events[e.port] += 1
        self.ports_all[e.port] += 1
        self.hosts_all[e.dst] += 1
        self.hours[e.ts.replace(minute=0, second=0, microsecond=0)] += 1
        if e.action == "blocked":
            self.blocked += 1
            self.dst_blocked[e.dst] += 1
            self.port_blocked[e.port] += 1

    def evict(self, cutoff) -> None:
        while self.dq and self.dq[0].ts < cutoff:
            e = self.dq.popleft()
            _dec_nested(self.ports_by_dst, e.dst, e.port)
            _dec_nested(self.hosts_by_port, e.port, e.dst)
            _dec(self.dst_events, e.dst)
            _dec(self.port_events, e.port)
            _dec(self.ports_all, e.port)
            _dec(self.hosts_all, e.dst)
            _dec(self.hours, e.ts.replace(minute=0, second=0, microsecond=0))
            if e.action == "blocked":
                self.blocked -= 1
                _dec(self.dst_blocked, e.dst)
                _dec(self.port_blocked, e.port)


_RANK = {"low": 0, "medium": 1, "high": 2}


def _severity(over: float, sensitive_hit: bool) -> str:
    score = over + (0.5 if sensitive_hit else 0.0)
    if score >= 3:
        return "high"
    if score >= 1.5:
        return "medium"
    return "low"


class PortScanDetector:
    def __init__(self, cfg: dict, allowlist: Allowlist | None = None):
        self.profiles = cfg["profiles"]
        self.cooldown = timedelta(seconds=cfg.get("cooldown_seconds", 900))
        self.sensitive = set(cfg.get("sensitive_ports", []))
        self.internal = [ipaddress.ip_network(n) for n in cfg.get("internal_networks", [])]
        self.allowlist = allowlist or Allowlist()
        self.stats: Counter = Counter()
        self._windows: dict[str, dict[str, _Window]] = {
            p["name"]: defaultdict(_Window) for p in self.profiles
        }
        self._last_alert: dict[tuple, tuple] = {}  # chave -> (último instante ativo, maior severidade)
        self._ratio_seen: set[tuple] = set()

    # ------------------------------------------------------------------ API
    def run(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []
        for ev in sorted(events, key=lambda e: e.ts):
            self.stats["events_total"] += 1
            reason = self._suppress_reason(ev)
            if reason:
                self.stats[f"suppressed_{reason}"] += 1
                continue
            for profile in self.profiles:
                alert = self._feed(profile, ev)
                if alert:
                    alerts.append(alert)
                    self.stats["alerts"] += 1
        return alerts

    # ------------------------------------------------------------- internals
    def _suppress_reason(self, ev: Event) -> str | None:
        if ev.src == ev.dst:
            return "self_traffic"
        if self.allowlist.ignores_destination(ev.dst):
            return "ignored_destination"
        if self.allowlist.source_name(ev.src):
            return "allowlist"
        if self.allowlist.port_exception(ev.src, ev.port):
            return "service_exception"
        return None

    def _scope(self, src: str) -> str:
        addr = ipaddress.ip_address(src)
        return "interno" if any(addr in n for n in self.internal) else "externo"

    def _feed(self, p: dict, ev: Event) -> Alert | None:
        w = self._windows[p["name"]][ev.src]
        w.add(ev)
        w.evict(ev.ts - timedelta(seconds=p["window_seconds"]))
        if len(w.dq) < p.get("min_events", 1):
            return None
        return self._evaluate(p, ev.src, w)

    def _evaluate(self, p: dict, src: str, w: _Window) -> Alert | None:
        kind = p["type"]
        if kind == "vertical":
            dst = max(w.ports_by_dst, key=lambda d: len(w.ports_by_dst[d]))
            ports = set(w.ports_by_dst[dst])
            if len(ports) < p["min_ports"]:
                return None
            rel_events, rel_failed = w.dst_events[dst], w.dst_blocked[dst]
            target, n_ports, n_hosts = dst, len(ports), 1
            over = n_ports / p["min_ports"]
        elif kind == "horizontal":
            port = max(w.hosts_by_port, key=lambda x: len(w.hosts_by_port[x]))
            hosts = w.hosts_by_port[port]
            if len(hosts) < p["min_hosts"]:
                return None
            ports = {port}
            rel_events, rel_failed = w.port_events[port], w.port_blocked[port]
            target, n_ports, n_hosts = f"*:{port}", 1, len(hosts)
            over = n_hosts / p["min_hosts"]
        else:  # block
            n_hosts, n_ports = len(w.hosts_all), len(w.ports_all)
            if n_hosts < p["min_hosts"] or n_ports < p["min_ports"]:
                return None
            ports = set(w.ports_all)
            rel_events, rel_failed = len(w.dq), w.blocked
            target = "*:*"
            over = min(n_hosts / p["min_hosts"], n_ports / p["min_ports"])

        if rel_events < p.get("min_events", 1):
            return None

        # Perfis lentos: espalhado por várias horas e com taxa baixa (scans rápidos
        # já são cobertos pelos perfis *_fast; evita alerta duplicado).
        active_hours = len(w.hours)
        if p.get("min_active_hours") and active_hours < p["min_active_hours"]:
            return None
        if p.get("max_events_per_hour") and rel_events / active_hours > p["max_events_per_hour"]:
            return None

        ratio = rel_failed / rel_events
        key = (p["name"], src, target)
        if ratio < p.get("min_fail_ratio", 0.0):
            if key not in self._ratio_seen:  # conta candidatos únicos, não reavaliações
                self._ratio_seen.add(key)
                self.stats["filtered_low_fail_ratio"] += 1
            return None

        now = w.dq[-1].ts
        sensitive_hit = sorted(ports & self.sensitive)
        severity = _severity(over, bool(sensitive_hit))
        rank = _RANK[severity]

        # Um alerta por campanha: o cooldown RENOVA enquanto o scan continua ativo e só
        # reemite se a severidade escalar (low -> medium -> high).
        last = self._last_alert.get(key)
        active = last is not None and now - last[0] < self.cooldown
        prev_rank = last[1] if active else -1
        self._last_alert[key] = (now, max(rank, prev_rank))
        if active and rank <= prev_rank:
            self.stats["deduplicated"] += 1
            return None
        if active:
            self.stats["escalated"] += 1

        scope = self._scope(src)
        return Alert(
            profile=p["name"],
            scan_type=kind,
            src_ip=src,
            src_scope=scope,
            target=target,
            first_seen=w.dq[0].ts.isoformat(),
            last_seen=now.isoformat(),
            events=rel_events,
            distinct_ports=n_ports,
            distinct_hosts=n_hosts,
            fail_ratio=round(ratio, 2),
            severity=severity,
            mitre="T1046" if scope == "interno" else "T1595.001",
            sensitive_ports_hit=sensitive_hit,
            sample_ports=sorted(ports)[:10],
        )
