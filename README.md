[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg)](https://www.python.org/)
# Authorized HTTP Load Testing Utility

This project is a **safe and controlled HTTP load-testing tool** for authorized environments
(lab, staging, or production systems where you have explicit written permission).

## Safety policy
- Public targets are blocked by default.
- Local/private targets are allowed (localhost, RFC1918 IP ranges, `.local`).
- To test a public host, you must explicitly add it with `--allow-hosts`.
- A kill switch file (`STOP_TEST` by default) can stop all workers immediately.

## Features
- Concurrency with configurable worker threads.
- Traffic profiles: `steady`, `ramp`, `spike`, `soak`.
- Global RPS cap (`--max-rps`).
- Optional proxy pool file.
- Real-time terminal output and final summary.
- JSON/CSV reporting for CI and post-analysis.
- P50/P95/P99 latency metrics.

## Install
```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install requests colorama click
```

## Usage
```bash
python Attack.py --url http://127.0.0.1:8080 --duration 20 --workers 10 --profile ramp --max-rps 50
```

### Public host test (explicit allow-list)
```bash
python Attack.py \
  --url https://example.com/health \
  --allow-hosts example.com \
  --duration 30 \
  --workers 12 \
  --profile steady \
  --max-rps 40
```

## Reports
```bash
python Attack.py \
  --url http://127.0.0.1:8080 \
  --output-json reports/summary.json \
  --output-csv reports/summary.csv
```

## Kill switch
During a test run, create the configured kill switch file to stop workers:
```bash
touch STOP_TEST
```

## Proxy file format
Use one proxy per line, comments start with `#`:
```text
# ip:port
127.0.0.1:8080
10.0.0.20:3128
```

## Legal notice
Use this tool only on systems you own or are formally authorized to test.
Unauthorized stress testing can be illegal and unethical.
