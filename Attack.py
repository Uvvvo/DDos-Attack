#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Safe HTTP load-testing utility for authorized environments.

Key safeguards:
- Defaults to localhost/private IP targets only.
- Requires explicit allow-list approval for public hosts.
- Supports kill-switch file to stop tests instantly.
- Applies max requests-per-second throttling.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import random
import statistics
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

import click
import requests
from colorama import Fore, Style, init
from requests import Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

init(autoreset=True)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


@dataclass
class RequestResult:
    status_code: Optional[int]
    latency_ms: float
    ok: bool
    error: Optional[str] = None


@dataclass
class SharedState:
    started_at: float
    finished_at: float = 0.0
    total: int = 0
    success: int = 0
    failure: int = 0
    latencies_ms: Optional[List[float]] = None
    status_counts: Optional[Dict[str, int]] = None
    error_counts: Optional[Dict[str, int]] = None

    def __post_init__(self) -> None:
        if self.latencies_ms is None:
            self.latencies_ms = []
        if self.status_counts is None:
            self.status_counts = {}
        if self.error_counts is None:
            self.error_counts = {}


def _retry_strategy() -> Retry:
    return Retry(
        total=2,
        backoff_factor=0.1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
    )


def create_session() -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=_retry_strategy(), pool_connections=200, pool_maxsize=200)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def parse_proxy_file(proxy_file: Optional[str]) -> List[str]:
    if not proxy_file:
        return []

    path = Path(proxy_file)
    if not path.exists():
        raise click.BadParameter(f"Proxy file not found: {proxy_file}")

    with path.open("r", encoding="utf-8") as file_handle:
        return [line.strip() for line in file_handle if line.strip() and not line.startswith("#")]


def host_is_private_or_local(hostname: Optional[str]) -> bool:
    if not hostname:
        return False
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return hostname.endswith(".local")


def validate_target(url: str, allow_hosts: List[str]) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise click.BadParameter("URL must start with http:// or https://")

    hostname = parsed.hostname
    if not hostname:
        raise click.BadParameter("URL is missing a hostname")

    if host_is_private_or_local(hostname):
        return hostname

    allowed = {item.strip().lower() for item in allow_hosts if item.strip()}
    if hostname.lower() not in allowed:
        raise click.BadParameter(
            "Public host blocked by safety policy. "
            "Use --allow-hosts with an explicit hostname for authorized testing."
        )

    return hostname


def profile_rps(profile: str, elapsed: float, duration: float, max_rps: float) -> float:
    if profile == "steady":
        return max_rps

    if profile == "ramp":
        ratio = min(1.0, elapsed / max(duration, 1e-6))
        return max(1.0, max_rps * ratio)

    if profile == "spike":
        cycle = int(elapsed) % 10
        return max_rps * (2.0 if cycle in {4, 5, 6} else 0.4)

    if profile == "soak":
        quarter = duration / 4
        if elapsed < quarter:
            return max_rps * 0.7
        if elapsed < 2 * quarter:
            return max_rps
        if elapsed < 3 * quarter:
            return max_rps * 0.8
        return max_rps * 0.6

    return max_rps


def percentile(data: List[float], p: float) -> float:
    if not data:
        return 0.0
    if len(data) == 1:
        return data[0]

    ordered = sorted(data)
    rank = (len(ordered) - 1) * p
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def issue_request(
    session: requests.Session,
    url: str,
    method: str,
    timeout: float,
    proxy: Optional[str] = None,
) -> RequestResult:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
    }

    proxies = None
    if proxy:
        proxy_url = proxy if proxy.startswith("http") else f"http://{proxy}"
        proxies = {"http": proxy_url, "https": proxy_url}

    start = time.perf_counter()
    try:
        response: Response = session.request(
            method=method,
            url=url,
            headers=headers,
            timeout=timeout,
            proxies=proxies,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        return RequestResult(
            status_code=response.status_code,
            latency_ms=elapsed_ms,
            ok=response.ok,
            error=None,
        )
    except requests.RequestException as exc:
        elapsed_ms = (time.perf_counter() - start) * 1000
        return RequestResult(status_code=None, latency_ms=elapsed_ms, ok=False, error=type(exc).__name__)


def worker(
    worker_id: int,
    state: SharedState,
    lock: threading.Lock,
    url: str,
    method: str,
    duration: float,
    timeout: float,
    profile: str,
    max_rps: float,
    kill_switch: Optional[Path],
    proxies: List[str],
    verbose: bool,
) -> None:
    session = create_session()
    local_sent = 0

    while True:
        now = time.monotonic()
        elapsed = now - state.started_at
        if elapsed >= duration:
            break

        if kill_switch and kill_switch.exists():
            if verbose:
                print(Fore.YELLOW + f"[worker {worker_id}] Kill-switch detected, stopping.")
            break

        current_rps = profile_rps(profile, elapsed, duration, max_rps)
        per_worker_rps = max(current_rps / max(1, threading.active_count() - 1), 0.5)
        sleep_s = 1.0 / per_worker_rps

        proxy = random.choice(proxies) if proxies else None
        result = issue_request(session, url, method, timeout, proxy)

        with lock:
            state.total += 1
            state.latencies_ms.append(result.latency_ms)
            if result.ok:
                state.success += 1
            else:
                state.failure += 1
            if result.status_code is not None:
                key = str(result.status_code)
                state.status_counts[key] = state.status_counts.get(key, 0) + 1
            elif result.error:
                state.error_counts[result.error] = state.error_counts.get(result.error, 0) + 1

        local_sent += 1
        if verbose and local_sent % 25 == 0:
            print(Fore.CYAN + f"[worker {worker_id}] sent={local_sent}")

        time.sleep(sleep_s)


def summarize(state: SharedState, duration: float) -> Dict[str, object]:
    lat = state.latencies_ms
    rps_achieved = state.total / max(duration, 1e-6)

    return {
        "duration_s": round(duration, 3),
        "requests_total": state.total,
        "requests_success": state.success,
        "requests_failure": state.failure,
        "success_rate": round((state.success / state.total) * 100, 2) if state.total else 0.0,
        "rps_achieved": round(rps_achieved, 3),
        "latency_ms": {
            "min": round(min(lat), 3) if lat else 0.0,
            "avg": round(statistics.fmean(lat), 3) if lat else 0.0,
            "p50": round(percentile(lat, 0.50), 3) if lat else 0.0,
            "p95": round(percentile(lat, 0.95), 3) if lat else 0.0,
            "p99": round(percentile(lat, 0.99), 3) if lat else 0.0,
            "max": round(max(lat), 3) if lat else 0.0,
        },
        "status_counts": dict(sorted(state.status_counts.items(), key=lambda item: int(item[0]))),
        "error_counts": dict(sorted(state.error_counts.items())),
    }


def print_summary(summary: Dict[str, object]) -> None:
    print(Fore.GREEN + "\n=== Load Test Summary ===")
    print(Fore.WHITE + f"Duration: {summary['duration_s']}s")
    print(Fore.WHITE + f"Total Requests: {summary['requests_total']}")
    print(Fore.WHITE + f"Success: {summary['requests_success']} | Failure: {summary['requests_failure']}")
    print(Fore.WHITE + f"Success Rate: {summary['success_rate']}%")
    print(Fore.WHITE + f"RPS Achieved: {summary['rps_achieved']}")

    latency = summary["latency_ms"]
    print(
        Fore.MAGENTA
        + (
            "Latency(ms) -> min:{min} avg:{avg} p50:{p50} p95:{p95} p99:{p99} max:{max}"
        ).format(**latency)
    )

    print(Fore.CYAN + f"HTTP Status Counts: {summary['status_counts']}")
    if summary["error_counts"]:
        print(Fore.YELLOW + f"Transport Errors: {summary['error_counts']}")


def write_json(output_path: str, summary: Dict[str, object]) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file_handle:
        json.dump(summary, file_handle, ensure_ascii=False, indent=2)


def write_csv(output_path: str, summary: Dict[str, object]) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    flat_rows = [
        ["duration_s", summary["duration_s"]],
        ["requests_total", summary["requests_total"]],
        ["requests_success", summary["requests_success"]],
        ["requests_failure", summary["requests_failure"]],
        ["success_rate", summary["success_rate"]],
        ["rps_achieved", summary["rps_achieved"]],
    ]
    for metric, value in summary["latency_ms"].items():
        flat_rows.append([f"latency_{metric}", value])
    for status, count in summary["status_counts"].items():
        flat_rows.append([f"status_{status}", count])
    for err, count in summary["error_counts"].items():
        flat_rows.append([f"error_{err}", count])

    with path.open("w", encoding="utf-8", newline="") as file_handle:
        writer = csv.writer(file_handle)
        writer.writerow(["metric", "value"])
        writer.writerows(flat_rows)


@click.command()
@click.option("--url", required=True, help="Target URL (authorized testing only).")
@click.option("--method", default="GET", show_default=True, type=click.Choice(["GET", "POST", "HEAD", "OPTIONS"]))
@click.option("--duration", default=30.0, show_default=True, type=float, help="Test duration in seconds.")
@click.option("--workers", default=8, show_default=True, type=int, help="Concurrent worker threads.")
@click.option(
    "--profile",
    default="steady",
    show_default=True,
    type=click.Choice(["steady", "ramp", "spike", "soak"]),
    help="Traffic pattern profile.",
)
@click.option("--max-rps", default=40.0, show_default=True, type=float, help="Global max requests per second cap.")
@click.option(
    "--allow-hosts",
    default="",
    show_default=True,
    help="Comma-separated explicit public host allow-list, e.g. example.com,api.example.com",
)
@click.option("--timeout", default=5.0, show_default=True, type=float, help="HTTP request timeout in seconds.")
@click.option("--proxy-file", default=None, help="Optional proxy list file (# comments supported).")
@click.option(
    "--kill-switch-file",
    default="STOP_TEST",
    show_default=True,
    help="If this file appears during a run, all workers stop.",
)
@click.option("--output-json", default="", help="Optional summary JSON output path.")
@click.option("--output-csv", default="", help="Optional summary CSV output path.")
@click.option("--verbose", is_flag=True, help="Verbose worker logs.")
def main(
    url: str,
    method: str,
    duration: float,
    workers: int,
    profile: str,
    max_rps: float,
    allow_hosts: str,
    timeout: float,
    proxy_file: Optional[str],
    kill_switch_file: str,
    output_json: str,
    output_csv: str,
    verbose: bool,
) -> None:
    """Run a safe, controlled HTTP load test in authorized environments."""
    if duration <= 0:
        raise click.BadParameter("--duration must be > 0")
    if workers <= 0:
        raise click.BadParameter("--workers must be > 0")
    if max_rps <= 0:
        raise click.BadParameter("--max-rps must be > 0")

    allow_list = [item.strip() for item in allow_hosts.split(",") if item.strip()]
    hostname = validate_target(url, allow_list)
    proxies = parse_proxy_file(proxy_file)

    print(Fore.GREEN + "Authorized HTTP Load Testing Utility")
    print(Fore.WHITE + f"Target: {url} (host={hostname})")
    print(Fore.WHITE + f"Workers: {workers} | Duration: {duration}s | Profile: {profile} | Max RPS: {max_rps}")
    print(Fore.WHITE + f"Proxy pool size: {len(proxies)}")
    print(Fore.YELLOW + f"Kill-switch file: {kill_switch_file}")

    state = SharedState(started_at=time.monotonic())
    lock = threading.Lock()
    kill_switch = Path(kill_switch_file) if kill_switch_file else None

    thread_list: List[threading.Thread] = []
    for idx in range(workers):
        thread = threading.Thread(
            target=worker,
            args=(
                idx + 1,
                state,
                lock,
                url,
                method,
                duration,
                timeout,
                profile,
                max_rps,
                kill_switch,
                proxies,
                verbose,
            ),
            daemon=True,
        )
        thread_list.append(thread)
        thread.start()

    for thread in thread_list:
        thread.join()

    state.finished_at = time.monotonic()
    actual_duration = max(state.finished_at - state.started_at, 0.001)

    summary = summarize(state, actual_duration)
    print_summary(summary)

    if output_json:
        write_json(output_json, summary)
        print(Fore.GREEN + f"JSON report written: {output_json}")
    if output_csv:
        write_csv(output_csv, summary)
        print(Fore.GREEN + f"CSV report written: {output_csv}")


if __name__ == "__main__":
    main()
