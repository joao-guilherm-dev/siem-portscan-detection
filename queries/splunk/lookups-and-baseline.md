# Splunk — configuração dos lookups e baseline

## 1. Lookups com match por CIDR

`transforms.conf`:

```ini
[portscan_allowlist]
filename = portscan_allowlist.csv
match_type = CIDR(cidr)

[portscan_service_exceptions]
filename = portscan_service_exceptions.csv
match_type = CIDR(cidr)
```

Gere os CSVs a partir da fonte única (`config/allowlist.yml`):

```bash
python -m portscan_detection export-allowlist --format splunk --output-dir exports/splunk
```

Copie `portscan_allowlist.csv` e `portscan_service_exceptions.csv` para o app (`lookups/`).

## 2. Baseline para calibrar os limiares (rode por 7–14 dias antes de ativar o alerta)

```spl
index=network earliest=-14d@d
| bin _time span=5m
| stats dc(dest_port) AS ports_5m BY _time src_ip dest_ip
| stats perc50(ports_5m) AS p50 perc95(ports_5m) AS p95 perc99(ports_5m) AS p99 max(ports_5m) AS max
```

Regra prática: limiar ≥ **p99 do baseline** (e nunca abaixo de 20 portas). Quem passa do p99 em uma janela de 5 min
sem estar na allowlist é candidato real a scan; quem fica sempre acima do limiar é fonte recorrente de falso positivo
e deve virar allowlist (com dono e data de revisão) — não limiar maior.

## 3. Top "ofensores" legítimos (candidatos à allowlist)

```spl
index=network earliest=-7d@d
| bin _time span=5m
| stats dc(dest_port) AS ports dc(dest_ip) AS hosts BY _time src_ip
| where ports>=20 OR hosts>=15
| stats count AS vezes_acima_do_limiar max(ports) AS max_portas max(hosts) AS max_hosts BY src_ip
| sort - vezes_acima_do_limiar
```
