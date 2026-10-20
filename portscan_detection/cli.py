"""Interface de linha de comando."""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from pathlib import Path

from .allowlist import Allowlist
from .config import load_yaml, validate_thresholds
from .detector import PortScanDetector
from .events import load_events
from .exporter import export_allowlist
from .generator import generate_rows, write_csv

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_THRESHOLDS = str(ROOT / "config" / "thresholds.yml")
DEFAULT_ALLOWLIST = str(ROOT / "config" / "allowlist.yml")


def _print_table(alerts: list[dict], out) -> None:
    if not alerts:
        print("Nenhum alerta.", file=out)
        return
    cols = [("severity", "SEV"), ("profile", "PERFIL"), ("src_ip", "ORIGEM"), ("src_scope", "ESCOPO"),
            ("target", "ALVO"), ("distinct_ports", "PORTAS"), ("distinct_hosts", "HOSTS"),
            ("fail_ratio", "FALHA"), ("mitre", "MITRE"), ("first_seen", "INÍCIO")]
    widths = [max(len(h), *(len(str(a[k])) for a in alerts)) for k, h in cols]
    print("  ".join(h.ljust(w) for (_, h), w in zip(cols, widths)), file=out)
    print("  ".join("-" * w for w in widths), file=out)
    for a in alerts:
        print("  ".join(str(a[k]).ljust(w) for (k, _), w in zip(cols, widths)), file=out)


def _print_csv(alerts: list[dict], out) -> None:
    if not alerts:
        return
    writer = csv.DictWriter(out, fieldnames=list(alerts[0].keys()))
    writer.writeheader()
    for a in alerts:
        writer.writerow({k: (";".join(map(str, v)) if isinstance(v, list) else v) for k, v in a.items()})


def cmd_detect(args) -> int:
    cfg = validate_thresholds(load_yaml(args.config))
    allow_cfg = load_yaml(args.allowlist)
    if args.no_allowlist:  # mantém só descarte estrutural (multicast/broadcast)
        allow_cfg = {"ignore_destination_cidrs": allow_cfg.get("ignore_destination_cidrs", [])}
    detector = PortScanDetector(cfg, Allowlist(allow_cfg))
    events, bad = load_events(args.input)
    alerts = [a.to_dict() for a in detector.run(events)]

    out = open(args.output, "w", encoding="utf-8", newline="") if args.output else sys.stdout
    try:
        if args.format == "json":
            json.dump(alerts, out, indent=2, ensure_ascii=False)
            out.write("\n")
        elif args.format == "csv":
            _print_csv(alerts, out)
        else:
            _print_table(alerts, out)
    finally:
        if args.output:
            out.close()

    print("\n== Estatísticas ==", file=sys.stderr)
    print(f"linhas inválidas ignoradas: {bad}", file=sys.stderr)
    for key in ("events_total", "suppressed_allowlist", "suppressed_service_exception",
                "suppressed_ignored_destination", "filtered_low_fail_ratio", "deduplicated", "escalated", "alerts"):
        print(f"{key}: {detector.stats.get(key, 0)}", file=sys.stderr)
    return 2 if (args.fail_on_alert and alerts) else 0


def cmd_generate(args) -> int:
    rows = generate_rows(seed=args.seed, hours=args.hours)
    write_csv(args.output, rows)
    print(f"{len(rows)} eventos gerados em {args.output}")
    return 0


def cmd_export(args) -> int:
    files = export_allowlist(load_yaml(args.allowlist), args.format)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        (out_dir / name).write_text(content, encoding="utf-8")
        print(f"gerado: {out_dir / name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="portscan_detection", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    d = sub.add_parser("detect", help="detecta port scans em um CSV de conexões")
    d.add_argument("--input", required=True, help="CSV: timestamp,src_ip,dst_ip,dst_port,action")
    d.add_argument("--config", default=DEFAULT_THRESHOLDS)
    d.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    d.add_argument("--no-allowlist", action="store_true", help="ignora a allowlist (mostra o ruído bruto)")
    d.add_argument("--format", choices=["table", "json", "csv"], default="table")
    d.add_argument("--output", help="arquivo de saída (padrão: stdout)")
    d.add_argument("--fail-on-alert", action="store_true", help="exit code 2 se houver alertas (CI)")
    d.set_defaults(func=cmd_detect)

    g = sub.add_parser("generate", help="gera logs sintéticos para testes")
    g.add_argument("--output", required=True)
    g.add_argument("--seed", type=int, default=42)
    g.add_argument("--hours", type=int, default=8)
    g.set_defaults(func=cmd_generate)

    e = sub.add_parser("export-allowlist", help="exporta a allowlist para Splunk/Sentinel/Elastic")
    e.add_argument("--format", required=True, choices=["splunk", "sentinel", "elastic"])
    e.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    e.add_argument("--output-dir", default="exports")
    e.set_defaults(func=cmd_export)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    args = build_parser().parse_args(argv)
    return args.func(args)
