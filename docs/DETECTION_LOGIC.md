# Lógica de detecção

## 1. Taxonomia de scans

| Tipo | Padrão | Objetivo do atacante | Perfil |
|---|---|---|---|
| **Vertical** | 1 origem → 1 destino → muitas portas | Mapear serviços de um alvo | PS-001 |
| **Horizontal** | 1 origem → muitos hosts → 1 porta | Achar hosts com um serviço específico (445, 3389, 22) | PS-002 |
| **Block** | 1 origem → muitos hosts × muitas portas | Mapear uma sub-rede inteira | PS-003 |
| **Low-and-slow** | Qualquer padrão acima, espalhado por horas | Fugir de limiares de janela curta | PS-004 |
| **Stealth (flags)** | SYN-only, FIN/NULL/Xmas | Evitar logs de aplicação / alguns firewalls | PS-006 (Zeek `conn_state`) |
| **Distribuído** | Muitos IPs, poucas portas cada | Fugir da agregação por origem | Roadmap |

## 2. Sinais usados (e por quê)

| Sinal | Uso | Observação |
|---|---|---|
| Portas distintas por (origem, destino) | Scan vertical | Contar **distintos**, não eventos: um cliente com 1000 conexões na 443 não é scan |
| Hosts distintos por (origem, porta) | Scan horizontal | Mesma ideia, no eixo dos hosts |
| **Taxa de falha/bloqueio** | Filtro principal anti-FP | Calculada **apenas sobre os eventos relevantes ao alvo** (não diluída por tráfego normal da mesma origem) |
| Volume mínimo de eventos | Piso de confiança | Evita alertar com 20 portas em 20 eventos de uma única sessão anômala |
| Porta sensível | Severidade | 21, 22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5985/6, 6379, 9200, 27017… |
| Escopo interno/externo | Severidade e MITRE | Interno → T1046; externo → T1595.001 |
| Horas ativas e taxa por hora | Distinguir lento de rápido | PS-004 só dispara com taxa baixa, evitando duplicar PS-001..003 |

## 3. Perfis e limiares-padrão

Definidos em [`config/thresholds.yml`](../config/thresholds.yml) e replicados nas queries.

| Perfil | Janela | Condição | Falha mín. |
|---|---|---|---|
| `ps001_vertical_fast` | 5 min | ≥ 20 portas/destino, ≥ 20 eventos | 50% |
| `ps002_horizontal_fast` | 5 min | ≥ 15 hosts/porta, ≥ 15 eventos | 50% |
| `ps003_block_fast` | 10 min | ≥ 5 hosts e ≥ 10 portas, ≥ 30 eventos | 50% |
| `ps004_vertical_slow` | 6 h (ref.) / 24 h (SIEM) | ≥ 40 portas, ≥ 40 eventos, ≥ 4 h ativas, ≤ 60 ev/h | 70% |
| `ps004_horizontal_slow` | 6 h (ref.) / 24 h (SIEM) | ≥ 40 hosts, ≥ 40 eventos, ≥ 4 h ativas, ≤ 60 ev/h | 70% |

Estes são **pontos de partida**. Calibre com o baseline do seu ambiente (veja `FALSE_POSITIVES.md`).

## 4. Mapeamento de campos por plataforma

| Conceito | Genérico | Splunk (CIM) | Elastic (ECS) | Sentinel (CEF) | Zeek |
|---|---|---|---|---|---|
| Origem | `src_ip` | `src_ip` | `source.ip` | `SourceIP` | `id.orig_h` |
| Destino | `dst_ip` | `dest_ip` | `destination.ip` | `DestinationIP` | `id.resp_h` |
| Porta destino | `dst_port` | `dest_port` | `destination.port` | `DestinationPort` | `id.resp_p` |
| Ação/resultado | `action` | `action` | `event.action` / `event.outcome` | `DeviceAction` | `conn_state` |

## 5. Mapeamento MITRE ATT&CK

- **T1046 — Network Service Discovery** (Discovery): scan a partir de um host interno (movimento lateral/pós-comprometimento).
- **T1595.001 — Active Scanning: Scanning IP Blocks** (Reconnaissance): varredura externa de faixas de IP.
- **T1595.002 — Vulnerability Scanning**: scans seguidos de sondagem de serviço (extensão futura).

## 6. Decisões de projeto

- **Janela deslizante com contadores incrementais** (implementação Python): evita recalcular a janela a cada evento; custo por evento ≈ O(1) amortizado + O(#destinos) para escolher o alvo dominante.
- **Dedup por campanha:** o cooldown *renova* enquanto o scan continua e só re-arma após silêncio. Reemite apenas quando a severidade escala, para o analista ver a evolução sem receber dezenas de alertas.
- **Taxa de falha por alvo:** em PS-001 calcula-se sobre os eventos daquele destino; em PS-002, sobre os da porta; em PS-003, sobre toda a janela da origem.
- **Allowlist como dado, não como código:** uma fonte (`allowlist.yml`) exportada para cada SIEM, evitando divergência entre plataformas.

## 7. Limitações e roadmap

- [ ] Scans **distribuídos**: agregar por destino/ASN e por assinatura de comportamento.
- [ ] Enriquecimento com **threat intel** (GreyNoise/AbuseIPDB) e rebaixamento automático de ruído de internet.
- [ ] Correlação **scan → sucesso**: elevar para alta quando a mesma origem autentica ou conecta com sucesso após o scan.
- [ ] Detecção por **flags TCP** (FIN/NULL/Xmas) em Packetbeat/Suricata.
- [ ] Cobertura **UDP** com ICMP port-unreachable.
- [ ] Exportador de regras Sigma → backends (CI com sigma-cli).
