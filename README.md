# 🔎 SIEM Port Scan Detection

Detecção de **port scan e atividades de reconhecimento** com queries prontas para **Splunk, Elastic, Microsoft Sentinel e Sigma**, desenhadas com foco em **reduzir falsos positivos**, mais uma implementação de referência em Python (com testes) que valida a lógica contra logs sintéticos.

[![CI](https://github.com/joao-guilherm-dev/siem-portscan-detection/actions/workflows/ci.yml/badge.svg)](https://github.com/joao-guilherm-dev/siem-portscan-detection/actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![MITRE](https://img.shields.io/badge/MITRE-T1046%20%7C%20T1595.001-red)

> Detection-as-code: lógica versionada, limiares em arquivo de configuração, allowlist com governança e testes automatizados rodando no CI.

---

## Por que este projeto

Regras ingênuas de port scan ("N portas em M minutos") geram alertas demais: scanners de vulnerabilidade, monitoramento, health checks de load balancer e aplicações com portas dinâmicas parecem scans. O analista aprende a ignorar o alerta — e o scan real passa batido.

A abordagem aqui combina **sinais independentes** antes de alertar:

| Camada | O que faz | Falso positivo que elimina |
|---|---|---|
| 1. Descarte estrutural | Ignora multicast, broadcast e link-local como destino | mDNS, SSDP, LLMNR, NetBIOS |
| 2. Allowlist com governança | Origens autorizadas (dono + motivo + data de revisão) | Nessus/Qualys, Zabbix/Nagios |
| 3. Exceção por serviço | Isenta origem apenas em portas específicas | Health check de LB em 443/8443 |
| 4. Volume mínimo | Exige N eventos além das contagens distintas | Rajadas curtas e eventos isolados |
| 5. **Taxa de falha/bloqueio** | Scan toca muitas portas *fechadas*; tráfego legítimo é majoritariamente bem-sucedido | App com portas RPC dinâmicas, polling de monitoramento |
| 6. Dedup por campanha | Um alerta por scan; reemite só se a severidade escalar | Alert fatigue em scans longos |
| 7. Enriquecimento/severidade | Porta sensível, escopo interno/externo, mapeamento MITRE | Priorização de triagem |

## Detecções

| ID | Detecção | Lógica | Janela | MITRE |
|---|---|---|---|---|
| **PS-001** | Port scan vertical | ≥ 20 portas distintas em **um** destino, ≥ 50% bloqueado | 5 min | T1046 / T1595.001 |
| **PS-002** | Port scan horizontal | **uma** porta em ≥ 15 hosts distintos, ≥ 50% bloqueado | 5 min | T1046 / T1595.001 |
| **PS-003** | Block scan | ≥ 5 hosts **e** ≥ 10 portas, ≥ 30 eventos | 10 min | T1046 / T1595.001 |
| **PS-004** | Scan lento (low-and-slow) | ≥ 40 portas em ≥ 4 horas ativas, ≤ 60 ev/h, ≥ 70% bloqueado | 24 h | T1595.001 / T1046 |
| **PS-005** | Scan a partir de endpoint / contra endpoint | Windows Filtering Platform (5157) e Defender for Endpoint | 5–10 min | T1046 |
| **PS-006** | Scan via Zeek | `conn_state` ∈ {S0, REJ, RSTOS0, SH} | 5 min | T1046 / T1595.001 |

Limiares-padrão em [`config/thresholds.yml`](config/thresholds.yml) (e mantidos em sincronia com as queries por teste automatizado).

## Estrutura

```
siem-portscan-detection/
├── queries/
│   ├── splunk/      # SPL (PS-001..006) + lookups e baseline
│   ├── elastic/     # ES|QL (PS-001..004) + regra threshold (JSON)
│   ├── sentinel/    # KQL (PS-001..005) + analytic rule (YAML)
│   └── sigma/       # regra base + correlações (value_count)
├── config/
│   ├── thresholds.yml   # perfis de detecção e limiares
│   └── allowlist.yml    # fonte única da allowlist (dono, motivo, revisão)
├── portscan_detection/  # implementação de referência (Python)
├── tests/               # unitários, ponta a ponta e validação dos artefatos
├── docs/
│   ├── DETECTION_LOGIC.md   # taxonomia de scans, fontes de dados, limitações
│   ├── FALSE_POSITIVES.md   # catálogo de FPs e metodologia de tuning
│   └── LAB_TESTING.md       # como validar com nmap em laboratório próprio
└── .github/workflows/ci.yml
```

## Quickstart

```bash
git clone https://github.com/joao-guilherm-dev/siem-portscan-detection.git
cd siem-portscan-detection
pip install -r requirements.txt

make test        # 65 testes
make demo        # gera ~26 mil eventos sintéticos e roda a detecção
make demo-raw    # mesmo log SEM allowlist: veja o ruído que as camadas evitam
```

### O cenário de demonstração

O gerador sintético mistura tráfego normal com **4 scans reais** e **4 fontes clássicas de falso positivo**:

| Origem | O que é | Resultado esperado |
|---|---|---|
| `203.0.113.45` | Scan vertical externo (300 portas em 2 min) | ✅ alerta PS-001 (escala low → high) |
| `10.20.1.77` | Scan horizontal interno na 445 (movimento lateral) | ✅ alerta PS-002 |
| `203.0.113.88` | Block scan (10 hosts × 15 portas) | ✅ alerta PS-003 |
| `192.0.2.99` | Scan lento (1 porta a cada ~4 min por 8 h) | ✅ alerta PS-004 |
| `10.10.50.5` | Scanner de vulnerabilidades (Nessus) | 🚫 allowlist |
| `10.10.60.10` | Monitoramento (Zabbix) | 🚫 allowlist (e taxa de falha ~10%) |
| `10.10.70.2` | Health check de load balancer | 🚫 exceção por serviço (443/8443) |
| `10.20.9.9` | App com portas dinâmicas, tudo permitido | 🚫 taxa de falha = 0% |

Os testes `tests/test_end_to_end.py` garantem que **exatamente** os 4 verdadeiros positivos geram alerta — e que, sem a allowlist, o scanner e o health check *viram* falsos positivos (provando que cada camada tem função).

### CLI

```bash
python -m portscan_detection detect --input logs.csv --format json --output alertas.json
python -m portscan_detection generate --output out/synthetic.csv --seed 42
python -m portscan_detection export-allowlist --format splunk --output-dir exports/splunk
```

Formato do CSV de entrada: `timestamp,src_ip,dst_ip,dst_port,action` (ISO-8601; `action` aceita allow/deny/drop/reject e estados do Zeek).

## Implantando nos SIEMs

1. **Calibre antes de ativar.** Rode a query de baseline ([`queries/splunk/lookups-and-baseline.md`](queries/splunk/lookups-and-baseline.md)) por 7–14 dias e ajuste os limiares ao p99 do seu ambiente.
2. **Exporte a allowlist** da fonte única (`config/allowlist.yml`):
   - **Splunk:** `export-allowlist --format splunk` → CSVs para lookups com `match_type = CIDR(cidr)`.
   - **Sentinel:** `export-allowlist --format sentinel` → importar como watchlist `PortScanAllowlist` (SearchKey = `cidr`).
   - **Elastic:** `export-allowlist --format elastic` → lista de valores do tipo `ip_range` para exceções da regra.
3. **Ative em modo sombra** (apenas registrar/tag, sem notificar) por 1–2 semanas e meça a precisão.
4. **Promova a alerta** com throttle por origem+alvo (15 min) e playbook de triagem.

Mapeie os nomes de campo ao seu ambiente (ECS no Elastic, CIM no Splunk, `CommonSecurityLog` no Sentinel). Os pontos de ajuste (`index`, `sourcetype`, tabela) estão no cabeçalho de cada query.

## Triagem sugerida

1. A origem está na allowlist ou em um bloco de scanner conhecido? Revise a data de revisão da entrada.
2. Alguma porta **foi permitida** (conexão estabelecida)? Scan + sucesso em porta sensível = prioridade alta.
3. Houve autenticação, exploit ou tráfego do mesmo IP logo após o scan? Correlacione.
4. Origem **interna** → possível movimento lateral (T1046), isole o host. Origem **externa** → enriqueça (GreyNoise, Shodan): ruído de internet inteira tem prioridade menor.

## Limitações conhecidas

- **Scans distribuídos** (muitos IPs, poucas portas cada) não são agregados por origem — exigem correlação por destino/ASN.
- **UDP** é pouco observável: sem handshake, a "falha" depende de ICMP unreachable ou de logs do firewall.
- **NAT/proxy:** vários usuários atrás de um IP podem elevar contagens; use a identidade do usuário/dispositivo quando disponível.
- Firewalls que **só logam bloqueios** (ou só permitidos) distorcem a taxa de falha — ajuste conforme a política de log.
- A implementação Python é de **referência e validação**: não substitui o SIEM em produção.

Detalhes e roadmap em [`docs/DETECTION_LOGIC.md`](docs/DETECTION_LOGIC.md) e [`docs/FALSE_POSITIVES.md`](docs/FALSE_POSITIVES.md).

## Aviso legal

Use scanners (nmap etc.) **somente em ambientes seus ou com autorização por escrito**. O objetivo deste repositório é defesa: detecção, tuning e validação em laboratório.

## Licença

MIT — veja [LICENSE](LICENSE).
