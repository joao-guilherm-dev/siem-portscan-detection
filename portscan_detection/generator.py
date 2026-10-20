"""Gerador de logs sintéticos de firewall (tráfego normal + ruído + scans reais).

Usa apenas faixas de documentação (RFC 5737) para IPs externos. Cenários:
  Verdadeiros positivos
    TP1  203.0.113.45 -> 198.51.100.10   scan vertical (300 portas em 2 min)
    TP2  10.20.1.77   -> 10.30.0.0/24    scan horizontal na 445 (movimento lateral)
    TP3  203.0.113.88 -> 10 hosts x 15 portas (block scan)
    TP4  192.0.2.99   -> 198.51.100.10   scan lento (1 porta a cada ~4 min)
  Falsos positivos clássicos
    FP1  10.10.50.5   scanner de vulnerabilidades (allowlist)
    FP2  10.10.60.10  servidor de monitoramento (allowlist / baixa taxa de falha)
    FP3  10.10.70.2   health check de load balancer (exceção por serviço)
    FP4  10.20.9.9    app com portas dinâmicas RPC, tudo permitido (taxa de falha)
"""
from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta

DEFAULT_START = datetime(2026, 10, 19, 8, 0, 0)


def generate_rows(seed: int = 42, hours: int = 8, start: datetime | None = None) -> list[tuple]:
    rng = random.Random(seed)
    start = start or DEFAULT_START
    end = start + timedelta(hours=hours)
    rows: list[tuple] = []

    def add(ts, src, dst, port, action):
        rows.append((ts, src, dst, port, action))

    # --- tráfego normal: 30 clientes falando com 5 servidores em portas comuns
    servers = ["10.30.0.10", "10.30.0.11", "10.30.0.12", "10.30.0.53", "10.30.0.50"]
    common_ports = [80, 443, 53, 445, 389]
    for i in range(10, 40):
        client = f"10.20.1.{i}"
        t = start + timedelta(seconds=rng.uniform(0, 60))
        while t < end:
            action = "deny" if rng.random() < 0.03 else "allow"
            add(t, client, rng.choice(servers), rng.choice(common_ports), action)
            t += timedelta(seconds=rng.uniform(30, 90))

    # --- FP2: monitoramento (SNMP/HTTPS) em 60 hosts a cada 10 min, ~10% de falha
    t = start
    rnd = 0
    while t < end:
        for i in range(1, 61):
            for port in (161, 443):
                action = "deny" if (i + rnd) % 10 == 0 else "allow"
                add(t + timedelta(seconds=rng.uniform(0, 20)), "10.10.60.10", f"10.30.1.{i}", port, action)
        rnd += 1
        t += timedelta(minutes=10)

    # --- FP1: scanner de vulnerabilidades (5 hosts x 1000 portas, 95% bloqueado)
    t0 = start + timedelta(hours=2)
    for host in range(10, 15):
        for port in range(1, 1001):
            action = "allow" if port % 20 == 0 else "deny"
            add(t0 + timedelta(seconds=rng.uniform(0, 120)), "10.10.50.5", f"10.30.0.{host}", port, action)

    # --- FP3: health check do LB em 40 hosts (60% indisponíveis) a cada hora
    t = start
    while t < end:
        for i in range(1, 41):
            action = "deny" if i % 5 < 3 else "allow"
            add(t + timedelta(seconds=rng.uniform(0, 30)), "10.10.70.2", f"10.30.2.{i}", 443, action)
        t += timedelta(hours=1)

    # --- FP4: app com portas dinâmicas (49152+) tudo permitido
    t0 = start + timedelta(hours=3)
    for port in rng.sample(range(49152, 65535), 40):
        add(t0 + timedelta(seconds=rng.uniform(0, 120)), "10.20.9.9", "10.30.0.50", port, "allow")

    # --- TP1: scan vertical externo
    t0 = start + timedelta(hours=4)
    for port in rng.sample(range(1, 1025), 300):
        action = "allow" if port in (80, 443) else "deny"
        add(t0 + timedelta(seconds=rng.uniform(0, 120)), "203.0.113.45", "198.51.100.10", port, action)

    # --- TP2: scan horizontal interno na 445
    t0 = start + timedelta(hours=5)
    for host in range(1, 255):
        action = "allow" if rng.random() < 0.15 else "deny"
        add(t0 + timedelta(seconds=rng.uniform(0, 180)), "10.20.1.77", f"10.30.0.{host}", 445, action)

    # --- TP3: block scan (10 hosts x 15 portas)
    t0 = start + timedelta(hours=6)
    scan_ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
    for host in range(20, 30):
        for port in scan_ports:
            add(t0 + timedelta(seconds=rng.uniform(0, 240)), "203.0.113.88", f"198.51.100.{host}", port, "deny")

    # --- TP4: scan lento (uma porta distinta a cada ~4 min)
    t = start + timedelta(minutes=10)
    slow_ports = rng.sample(range(1, 10000), 400)
    idx = 0
    while t < end and idx < len(slow_ports):
        add(t, "192.0.2.99", "198.51.100.10", slow_ports[idx], "deny")
        idx += 1
        t += timedelta(seconds=rng.uniform(200, 280))

    rows.sort(key=lambda r: r[0])
    return rows


def write_csv(path: str, rows: list[tuple]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "action"])
        for ts, src, dst, port, action in rows:
            writer.writerow([ts.isoformat() + "Z", src, dst, port, action])
