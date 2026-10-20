# Validação em laboratório

> ⚠️ Execute **somente em laboratório próprio** (VMs isoladas) ou com **autorização por escrito**. Nunca contra redes de terceiros.

## Topologia mínima

- 1 máquina "atacante" (Kali/Ubuntu com `nmap`).
- 1–N máquinas alvo (VMs com serviços simples; algumas com portas fechadas).
- Um firewall/gateway (pfSense, OPNsense, iptables) enviando logs ao SIEM — ou Zeek/Suricata em um *tap/span*.
- Logging habilitado para **bloqueios** (a taxa de falha depende disso).

## Casos de teste

| Detecção | Comando (no laboratório) | Esperado |
|---|---|---|
| PS-001 vertical | `nmap -sS -p 1-1000 <ALVO>` | Alerta com ~1000 portas, taxa de bloqueio alta |
| PS-002 horizontal | `nmap -sS -p 445 <SUB-REDE-LAB>/24` | Alerta com `dest_port=445`, severidade ≥ média |
| PS-003 block | `nmap -sS -p 21,22,23,25,80,443,445,3389,8080,8443 <SUB-REDE-LAB>/28` | Alerta de block scan |
| PS-004 lento | `nmap -sS -T0 -p 1-100 <ALVO>` (≈ 5 min entre sondagens; deixe rodar por horas) | Alerta de scan lento, **sem** PS-001 |
| PS-006 stealth | `nmap -sF -p 1-1000 <ALVO>` e `nmap -sN -p 1-1000 <ALVO>` | Alerta Zeek via `conn_state` (S0/SH/REJ) |

## Testes negativos (devem **não** alertar)

| Cenário | Como simular | Esperado |
|---|---|---|
| Scanner autorizado | Rodar o scan a partir de um IP presente na allowlist | Sem alerta (suprimido) |
| Navegação normal | Muitas conexões à 443 de um cliente | Sem alerta (poucas portas distintas) |
| Health check | Origem com exceção de serviço em 443 | Sem alerta |
| Tráfego multicast | mDNS/SSDP na rede de teste | Sem alerta |

## Registro de resultados

Documente por teste: horário, comando, detecção esperada, alerta obtido, latência (do evento ao alerta) e ajustes de limiar. Isso vira a evidência de cobertura do seu *detection-as-code*.

## Validação sem laboratório

`make demo` usa logs sintéticos (faixas RFC 5737 e privadas) e os testes automatizados cobrem os mesmos cenários — úteis para CI, mas não substituem o teste contra o seu pipeline real de logs.
