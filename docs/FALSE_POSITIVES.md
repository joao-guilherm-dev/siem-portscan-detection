# Falsos positivos: catálogo e metodologia de tuning

## 1. Catálogo de fontes de FP

| Fonte | Por que parece scan | Mitigação neste repo |
|---|---|---|
| **Scanners de vulnerabilidade** (Nessus, Qualys, OpenVAS) | É um scan — só que autorizado | `authorized_scanners` na allowlist, com dono e janela de revisão |
| **Monitoramento** (Zabbix, Nagios, PRTG, SNMP) | Polling em muitos hosts e portas | `monitoring` na allowlist; taxa de falha costuma ser baixa (já filtra) |
| **Health check de load balancer / service discovery** | Muitos hosts, mesma porta, alta falha em nós fora do ar | `service_exceptions` (origem isenta só em 443/8443) |
| **Aplicações com portas dinâmicas** (RPC 49152–65535) | Muitas portas distintas em um destino | Filtro de taxa de falha: conexões permitidas não contam |
| **Tráfego multicast/broadcast** (mDNS, SSDP, LLMNR, NetBIOS) | Muitos "destinos" | Descarte estrutural (224.0.0.0/4, 255.255.255.255, 169.254.0.0/16) |
| **Controladores de domínio / DHCP / DNS** | Alto fan-out legítimo | Allowlist por papel; baseline por origem |
| **NAT/proxy corporativo** | Muitos usuários sob um IP somam portas/hosts | Elevar limiares para esses IPs ou agregar por usuário/dispositivo |
| **Software de backup / inventário (SCCM, EDR)** | Conecta em toda a frota | Allowlist + exceção por porta |
| **Crawlers / CDN / uptime monitors externos** | Varredura externa recorrente | Rebaixar por threat intel / lista de provedores conhecidos |
| **Ruído de internet** (Shodan, Censys, bots) | Scan real, mas sem alvo específico | Prioridade menor; alertar quando houver **sucesso** de conexão ou alvo sensível |

## 2. Metodologia de tuning (passo a passo)

1. **Baseline (7–14 dias).** Meça `perc95/perc99/max` de portas distintas por origem/destino em 5 min (query em `queries/splunk/lookups-and-baseline.md`).
2. **Defina limiares ≥ p99** e nunca abaixo do piso razoável (20 portas / 15 hosts).
3. **Liste os "ofensores recorrentes"** (quem passa o limiar toda semana). Cada um vira uma decisão explícita: *allowlist* (com dono, motivo, revisão) ou *investigar*.
4. **Modo sombra (1–2 semanas).** A regra roda e registra, mas não notifica. Revise os resultados.
5. **Meça precisão.** `precisão = verdadeiros positivos / alertas`. Meta inicial sugerida: > 70%; abaixo disso, ajuste antes de promover.
6. **Promova a alerta** com throttle por origem+alvo (15 min) e playbook de triagem.
7. **Revise a allowlist periodicamente.** O código avisa quando `review_date` vence — exceção sem prazo vira ponto cego.
8. **Reteste a cada mudança** com `make test` e com os testes de laboratório (`LAB_TESTING.md`).

## 3. Princípio: allowlist, não limiar

Quando uma fonte legítima dispara a regra, a resposta correta quase nunca é **subir o limiar global** (isso cega a regra para scans reais). Prefira, nesta ordem:

1. **Exceção estreita** (origem + porta): `service_exceptions`.
2. **Allowlist da origem** com dono e data de revisão.
3. **Filtro comportamental** (taxa de falha, volume mínimo).
4. Só por último, ajustar o limiar — e com dados do baseline.

## 4. Governança da allowlist

Cada entrada em `config/allowlist.yml` tem:

- `name` — o que é;
- `owner` — quem responde por ela;
- `reason` — por que é legítima;
- `review_date` — quando deve ser reavaliada (aviso no CLI se vencida).

## 5. Como cada camada contribui (evidência nos testes)

`tests/test_end_to_end.py` roda o mesmo log com e sem allowlist:

- **Com allowlist:** exatamente 4 origens alertam (os scans reais).
- **Sem allowlist:** o scanner de vulnerabilidades e o health check do LB viram falsos positivos — mas o monitoramento e a aplicação de portas dinâmicas **continuam filtrados** pela taxa de falha.

Ou seja: a taxa de falha segura o que é "tráfego bem-sucedido em escala", e a allowlist cobre o que é "tráfego legitimamente barulhento".

## 6. Métricas recomendadas

| Métrica | Como medir |
|---|---|
| Precisão por regra | TP / alertas, por mês |
| Alertas por origem | Detecta ofensores recorrentes |
| Tempo até triagem | Mostra se a regra virou ruído |
| Entradas de allowlist vencidas | Higiene de exceções |
