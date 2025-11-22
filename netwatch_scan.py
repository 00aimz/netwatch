"""Network scanning logic for netwatch.

Provides utilities for parsing target ranges, probing host liveness,
scanning a small set of TCP ports, and aggregating results.
Only the Python standard library is used for portability.
"""
from __future__ import annotations

import ipaddress
import math
import os
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence
import shutil

DEFAULT_PORTS: Sequence[int] = (22, 80, 443, 3389, 8080)


@dataclass
class HostResult:
    """Represents the result of scanning a single host."""

    ip: str
    latency_ms: Optional[float]
    open_ports: List[int]


class TargetParseError(ValueError):
    """Raised when a target string cannot be parsed."""


def parse_targets(spec: str) -> List[str]:
    """Parse a CIDR, range, or single IP string into a list of IPs.

    Args:
        spec: CIDR ("192.168.1.0/24"), range ("192.168.1.1-192.168.1.20"),
            or single IPv4 address.

    Returns:
        Sorted list of IPv4 address strings.

    Raises:
        TargetParseError: If the specification is invalid or empty.
    """

    spec = spec.strip()
    if not spec:
        raise TargetParseError("Target specification cannot be empty.")

    if "/" in spec:
        try:
            network = ipaddress.ip_network(spec, strict=False)
        except ValueError as exc:
            raise TargetParseError(str(exc)) from exc
        return [str(ip) for ip in network.hosts()]

    if "-" in spec:
        start_str, end_str = spec.split("-", 1)
        try:
            start_ip = ipaddress.ip_address(start_str)
            end_ip = ipaddress.ip_address(end_str)
        except ValueError as exc:
            raise TargetParseError(str(exc)) from exc
        if start_ip.version != 4 or end_ip.version != 4:
            raise TargetParseError("Only IPv4 ranges are supported.")
        if int(end_ip) < int(start_ip):
            raise TargetParseError("Range end must be greater than or equal to start.")
        return [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]

    try:
        ip = ipaddress.ip_address(spec)
    except ValueError as exc:
        raise TargetParseError(str(exc)) from exc
    if ip.version != 4:
        raise TargetParseError("Only IPv4 addresses are supported.")
    return [str(ip)]


def _ping_host(ip: str, timeout: float) -> tuple[bool, Optional[float]]:
    """Attempt to ping a host using the system ping command.

    Returns a tuple of (is_reachable, latency_ms). The latency is measured
    wall-clock time of the ping invocation and may be None on failure.
    """

    ping_bin = shutil.which("ping")
    if not ping_bin:
        return False, None

    if platform.system().lower().startswith("win"):
        cmd = [ping_bin, "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        # On Unix, -W expects seconds and -c limits the count.
        cmd = [ping_bin, "-c", "1", "-W", str(max(1, int(math.ceil(timeout)))), ip]

    start = time.perf_counter()
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=max(timeout + 1.0, 2.0),
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False, None

    if result.returncode == 0:
        latency_ms = (time.perf_counter() - start) * 1000
        return True, latency_ms
    return False, None


def _tcp_probe(ip: str, port: int, timeout: float) -> Optional[float]:
    """Attempt a TCP connection to a host/port.

    Returns latency in milliseconds on success, otherwise None.
    """

    start = time.perf_counter()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
        except OSError:
            return None
    if result == 0:
        return (time.perf_counter() - start) * 1000
    return None


def scan_host(ip: str, ports: Sequence[int], timeout: float) -> Optional[HostResult]:
    """Scan a single host for liveness and open ports."""

    live, latency = _ping_host(ip, timeout)
    open_ports: List[int] = []

    if not live:
        # Fallback: check liveness via a quick TCP probe on known ports.
        for port in ports:
            probe_latency = _tcp_probe(ip, port, timeout)
            if probe_latency is not None:
                live = True
                latency = latency or probe_latency
                open_ports.append(port)
                break

    if not live:
        return None

    # If we became live via ping, now check the full port list.
    for port in ports:
        if port in open_ports:
            continue
        probe_latency = _tcp_probe(ip, port, timeout)
        if probe_latency is not None:
            open_ports.append(port)
            if latency is None:
                latency = probe_latency

    return HostResult(ip=ip, latency_ms=latency, open_ports=sorted(open_ports))


def scan_network(
    spec: str,
    ports: Optional[Iterable[int]] = None,
    timeout: float = 1.0,
    workers: Optional[int] = None,
) -> List[HostResult]:
    """Scan hosts defined by *spec* concurrently.

    Args:
        spec: Target specification (CIDR, range, or single IP).
        ports: Iterable of port numbers to scan. Defaults to :data:`DEFAULT_PORTS`.
        timeout: Socket timeout in seconds.
        workers: Number of worker threads; defaults to CPU count.

    Returns:
        List of :class:`HostResult` objects for responsive hosts.
    """

    target_ips = parse_targets(spec)
    port_list = list(ports or DEFAULT_PORTS)
    max_workers = workers or max(2, (os.cpu_count() or 2))

    results: List[HostResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(scan_host, ip, port_list, timeout): ip for ip in target_ips}
        for future in as_completed(future_map):
            host_result = future.result()
            if host_result:
                results.append(host_result)

    results.sort(key=lambda r: ipaddress.ip_address(r.ip))
    return results


__all__ = [
    "HostResult",
    "TargetParseError",
    "DEFAULT_PORTS",
    "parse_targets",
    "scan_host",
    "scan_network",
]
