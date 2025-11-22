"""Command line interface for the netwatch network scanner."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable, List

from netwatch_scan import DEFAULT_PORTS, HostResult, TargetParseError, scan_network


def parse_port_list(port_string: str) -> List[int]:
    """Parse a comma-separated port string into integers."""

    ports: List[int] = []
    for item in port_string.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            value = int(item)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid port value: {item}") from exc
        if value <= 0 or value > 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {value}")
        ports.append(value)
    if not ports:
        raise argparse.ArgumentTypeError("At least one port must be provided.")
    return ports


def _format_table(results: Iterable[HostResult]) -> str:
    rows = [(r.ip, f"{r.latency_ms:.1f}" if r.latency_ms is not None else "-", ','.join(str(p) for p in r.open_ports) or '-') for r in results]
    headers = ("IP Address", "Latency (ms)", "Open Ports")
    widths = [len(h) for h in headers]
    for ip, latency, ports in rows:
        widths[0] = max(widths[0], len(ip))
        widths[1] = max(widths[1], len(latency))
        widths[2] = max(widths[2], len(ports))
    line_fmt = (
        "{:<" + str(widths[0]) + "}  {:>" + str(widths[1]) + "}  {:<" + str(widths[2]) + "}"
    )
    parts = [line_fmt.format(*headers), line_fmt.format(*('─'*widths[0], '─'*widths[1], '─'*widths[2]))]
    for row in rows:
        parts.append(line_fmt.format(*row))
    return '\n'.join(parts)


def _format_summary(results: List[HostResult]) -> str:
    host_count = len(results)
    ports_seen = sorted({p for r in results for p in r.open_ports})
    return (
        f"Discovered {host_count} host(s).\n"
        f"Open ports observed: {', '.join(str(p) for p in ports_seen) if ports_seen else 'none'}."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local network scanner and host inventory tool.")
    parser.add_argument("target", metavar="CIDR_OR_RANGE", help="Target in CIDR (192.168.1.0/24) or range (192.168.1.1-192.168.1.20) format.")
    parser.add_argument("--ports", type=parse_port_list, default=None, help="Comma-separated list of ports to probe (default common set).")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default 1.0).")
    parser.add_argument("--workers", type=int, default=None, help="Number of concurrent workers (default: CPU count).")
    parser.add_argument("--json", dest="json_path", default=None, help="Write JSON report to the specified path.")
    parser.add_argument("--summary", action="store_true", help="Print only a summary instead of per-host details.")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse errors exit
        return 1 if exc.code else 0

    try:
        results = scan_network(
            args.target,
            ports=args.ports or DEFAULT_PORTS,
            timeout=args.timeout,
            workers=args.workers,
        )
    except TargetParseError as exc:
        sys.stderr.write(f"Invalid target: {exc}\n")
        return 1
    except Exception as exc:  # pragma: no cover - defensive
        sys.stderr.write(f"Runtime error: {exc}\n")
        return 2

    if args.json_path:
        try:
            with open(args.json_path, "w", encoding="utf-8") as f:
                json.dump(
                    [
                        {"ip": r.ip, "latency_ms": r.latency_ms, "open_ports": r.open_ports}
                        for r in results
                    ],
                    f,
                    indent=2,
                )
        except OSError as exc:
            sys.stderr.write(f"Failed to write JSON report: {exc}\n")
            return 2

    output = _format_summary(results) if args.summary else _format_table(results)
    print(output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
