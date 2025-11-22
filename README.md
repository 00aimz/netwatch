# netwatch

Local network scanner and host inventory tool implemented with the Python standard library.

## Features
- Discover live hosts within a CIDR block, single IP, or explicit range.
- ICMP ping first with graceful TCP connect fallback when ping is unavailable.
- Optional probing of common ports (default: 22, 80, 443, 3389, 8080) or a custom list.
- Concurrent scanning using worker threads for speed.
- Human-readable table output and optional JSON report generation.

## Installation
No external dependencies are required. Use Python 3.10+.

## Usage
```bash
python netwatch.py 192.168.1.0/24
python netwatch.py 192.168.1.1-192.168.1.50 --ports 22,80,443 --timeout 1.5
python netwatch.py 192.168.1.0/28 --summary --json results.json
```

### Arguments
- `CIDR_OR_RANGE` (positional): Target CIDR, range, or single IP.
- `--ports 22,80,443`: Comma-separated list of ports to scan (default common set).
- `--timeout SECONDS`: Socket timeout for probes (default: 1.0).
- `--workers N`: Number of concurrent worker threads (default: CPU count).
- `--json PATH`: Write JSON report to the provided path.
- `--summary`: Print a condensed summary instead of full details.

### Exit Codes
- `0`: Success.
- `1`: Invalid arguments.
- `2`: Runtime error.

## Development
Run the test suite with:
```bash
python -m unittest
```
