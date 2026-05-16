#!/usr/bin/env python3
"""
Keep a stable local SOCKS/HTTP proxy by switching between unstable Xray VLESS links.

The script measures "real delay" by starting a temporary Xray process per candidate,
making a real HTTP(S) request through that candidate, then keeping the fastest working
candidate alive on fixed local SOCKS and HTTP ports. If health checks fail, it re-tests
the list and switches to the best live candidate.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


DEFAULT_TEST_URLS = (
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
)

LOG_MODE = "minimal"
USE_COLOR = sys.stdout.isatty()

LOG_COLORS = {
    "system": "\033[37m",
    "test": "\033[36m",
    "select": "\033[1;32m",
    "health": "\033[35m",
    "retest": "\033[1;33m",
    "traffic": "\033[90m",
    "error": "\033[1;31m",
}
LOG_LABELS = {
    "system": "SYS",
    "test": "TEST",
    "select": "SELECT",
    "health": "HEALTH",
    "retest": "RETEST",
    "traffic": "TRAFFIC",
    "error": "ERROR",
}
MINIMAL_LOG_CATEGORIES = {"system", "test", "select", "health", "retest", "error"}
RESET_COLOR = "\033[0m"


def now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def configure_logging(mode: str, use_color: bool) -> None:
    global LOG_MODE, USE_COLOR
    LOG_MODE = mode
    USE_COLOR = use_color


def log(message: str, category: str = "system") -> None:
    if LOG_MODE == "minimal" and category not in MINIMAL_LOG_CATEGORIES:
        return

    label = LOG_LABELS.get(category, "LOG")
    line = f"[{now()}] [{label}] {message}"
    if USE_COLOR:
        color = LOG_COLORS.get(category, "")
        if color:
            line = f"{color}{line}{RESET_COLOR}"
    print(line, flush=True)


def as_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def first_query(params: dict[str, list[str]], *names: str, default: str = "") -> str:
    for name in names:
        values = params.get(name)
        if values:
            return values[0]
    return default


def parse_host_port(netloc: str) -> tuple[str, int]:
    if "@" in netloc:
        _, netloc = netloc.rsplit("@", 1)

    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            raise ValueError("Invalid IPv6 address in URL")
        host = netloc[1:end]
        rest = netloc[end + 1 :]
        if not rest.startswith(":"):
            raise ValueError("Missing port in URL")
        return host, int(rest[1:])

    if ":" not in netloc:
        raise ValueError("Missing port in URL")
    host, port = netloc.rsplit(":", 1)
    return host, int(port)


@dataclass(frozen=True)
class Candidate:
    index: int
    name: str
    uri: str
    outbound: dict[str, Any]


@dataclass(frozen=True)
class ProbeResult:
    candidate: Candidate
    ok: bool
    latency_ms: Optional[float]
    error: str = ""


def parse_vless_uri(uri: str, index: int) -> Candidate:
    parsed = urllib.parse.urlsplit(uri.strip())
    if parsed.scheme.lower() != "vless":
        raise ValueError("Only vless:// links are supported")

    user_id = urllib.parse.unquote(parsed.username or "")
    if not user_id:
        raise ValueError("Missing VLESS UUID")

    address, port = parse_host_port(parsed.netloc)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    name = urllib.parse.unquote(parsed.fragment or f"candidate-{index}")

    encryption = first_query(params, "encryption", default="none")
    flow = first_query(params, "flow")
    user: dict[str, Any] = {"id": user_id, "encryption": encryption}
    if flow:
        user["flow"] = flow

    network = first_query(params, "type", "network", default="tcp")
    security = first_query(params, "security", default="none")
    stream: dict[str, Any] = {"network": network}

    if security and security != "none":
        stream["security"] = security

    allow_insecure = as_bool(
        first_query(params, "allowInsecure", "insecure", default="0"),
        default=False,
    )
    sni = first_query(params, "sni", "serverName")
    fingerprint = first_query(params, "fp", "fingerprint")
    alpn = first_query(params, "alpn")

    if security == "tls":
        tls_settings: dict[str, Any] = {"allowInsecure": allow_insecure}
        if sni:
            tls_settings["serverName"] = sni
        if fingerprint:
            tls_settings["fingerprint"] = fingerprint
        if alpn:
            tls_settings["alpn"] = [item for item in alpn.split(",") if item]
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        reality_settings: dict[str, Any] = {}
        if sni:
            reality_settings["serverName"] = sni
        if fingerprint:
            reality_settings["fingerprint"] = fingerprint
        public_key = first_query(params, "pbk", "publicKey")
        short_id = first_query(params, "sid", "shortId")
        spider_x = first_query(params, "spx", "spiderX")
        if public_key:
            reality_settings["publicKey"] = public_key
        if short_id:
            reality_settings["shortId"] = short_id
        if spider_x:
            reality_settings["spiderX"] = spider_x
        stream["realitySettings"] = reality_settings

    attach_transport_settings(stream, network, params)

    outbound = {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream,
    }
    return Candidate(index=index, name=name, uri=uri.strip(), outbound=outbound)


def attach_transport_settings(
    stream: dict[str, Any], network: str, params: dict[str, list[str]]
) -> None:
    path = first_query(params, "path")
    host = first_query(params, "host")
    mode = first_query(params, "mode")
    extra_raw = first_query(params, "extra")

    if network == "xhttp":
        settings: dict[str, Any] = {}
        if path:
            settings["path"] = path
        if host:
            settings["host"] = host
        if mode:
            settings["mode"] = mode
        if extra_raw:
            try:
                settings["extra"] = json.loads(extra_raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid xhttp extra JSON: {exc}") from exc
        stream["xhttpSettings"] = settings
        return

    if network == "splithttp":
        settings = {}
        if path:
            settings["path"] = path
        if host:
            settings["host"] = host
        if mode:
            settings["mode"] = mode
        if extra_raw:
            try:
                settings["extra"] = json.loads(extra_raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid splithttp extra JSON: {exc}") from exc
        stream["splithttpSettings"] = settings
        return

    if network == "ws":
        settings = {}
        if path:
            settings["path"] = path
        if host:
            settings["headers"] = {"Host": host}
        stream["wsSettings"] = settings
        return

    if network == "httpupgrade":
        settings = {}
        if path:
            settings["path"] = path
        if host:
            settings["host"] = host
        stream["httpupgradeSettings"] = settings
        return

    if network in {"h2", "http"}:
        settings = {}
        if path:
            settings["path"] = path
        if host:
            settings["host"] = [item for item in host.split(",") if item]
        stream["httpSettings"] = settings
        stream["network"] = "http"
        return

    if network == "grpc":
        service_name = first_query(params, "serviceName", "path")
        settings = {}
        if service_name:
            settings["serviceName"] = service_name.lstrip("/")
        if mode == "multi":
            settings["multiMode"] = True
        stream["grpcSettings"] = settings
        return

    if network == "tcp":
        header_type = first_query(params, "headerType", default="none")
        if header_type != "none":
            stream["tcpSettings"] = {"header": {"type": header_type}}


def load_candidates(path: Path) -> list[Candidate]:
    candidates: list[Candidate] = []
    errors: list[str] = []

    for raw_index, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            candidates.append(parse_vless_uri(line, len(candidates) + 1))
        except Exception as exc:
            errors.append(f"line {raw_index}: {exc}")

    for item in errors:
        log(f"Skipped invalid config: {item}", "error")

    if not candidates:
        raise RuntimeError("No valid VLESS configs were found")
    return candidates


def find_free_port(bind: str) -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, 0))
        return int(sock.getsockname()[1])


def proxy_connect_host(bind: str) -> str:
    if bind in {"0.0.0.0", "::"}:
        return "127.0.0.1"
    return bind


def wait_for_port(bind: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((bind, port)) == 0:
                return True
        time.sleep(0.05)
    return False


def build_xray_config(
    candidate: Candidate,
    bind: str,
    socks_port: Optional[int],
    http_port: Optional[int],
    log_level: str,
) -> dict[str, Any]:
    inbounds: list[dict[str, Any]] = []
    if socks_port is not None:
        inbounds.append(
            {
                "tag": "socks-in",
                "listen": bind,
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
            }
        )
    if http_port is not None:
        inbounds.append(
            {
                "tag": "http-in",
                "listen": bind,
                "port": http_port,
                "protocol": "http",
                "settings": {},
            }
        )

    outbound = json.loads(json.dumps(candidate.outbound))
    outbound["tag"] = "proxy"

    return {
        "log": {"loglevel": log_level},
        "inbounds": inbounds,
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": [item["tag"] for item in inbounds],
                    "outboundTag": "proxy",
                }
            ],
        },
    }


def write_config(config: dict[str, Any]) -> str:
    handle = tempfile.NamedTemporaryFile(
        mode="w",
        prefix="xray-autoswitch-",
        suffix=".json",
        encoding="utf-8",
        delete=False,
    )
    with handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
    return handle.name


def start_xray(xray_bin: str, config_path: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [xray_bin, "run", "-c", config_path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )


def signal_process(process: subprocess.Popen[str], sig: int) -> None:
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(process.pid, sig)
        return
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        process.send_signal(sig)


def stop_process(process: Optional[subprocess.Popen[str]], timeout: float = 2.0) -> None:
    if process is None or process.poll() is not None:
        return
    signal_process(process, signal.SIGTERM)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        signal_process(process, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.wait(timeout=timeout)
    if process.stdout is not None:
        with contextlib.suppress(OSError):
            process.stdout.close()


def request_via_http_proxy(url: str, proxy_port: int, bind: str, timeout: float) -> None:
    proxy = f"http://{proxy_connect_host(bind)}:{proxy_port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "xray-autoswitch/1.0",
            "Cache-Control": "no-cache",
        },
    )
    with opener.open(request, timeout=timeout) as response:
        response.read(1)
        if response.status >= 500:
            raise RuntimeError(f"HTTP status {response.status}")


def run_xray_config_test(xray_bin: str, config_path: str) -> tuple[bool, str]:
    result = subprocess.run(
        [xray_bin, "run", "-test", "-c", config_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.returncode == 0, result.stdout.strip()


def probe_candidate(
    candidate: Candidate,
    args: argparse.Namespace,
    config_test_only: bool = False,
) -> ProbeResult:
    temp_http_port = args.http_port if config_test_only else find_free_port(args.bind)
    config_path = ""
    process: Optional[subprocess.Popen[str]] = None
    try:
        config = build_xray_config(
            candidate=candidate,
            bind=args.bind,
            socks_port=None,
            http_port=temp_http_port,
            log_level=args.xray_log_level,
        )
        config_path = write_config(config)

        if config_test_only:
            ok, output = run_xray_config_test(args.xray_bin, config_path)
            if ok:
                return ProbeResult(candidate, True, 0.0)
            return ProbeResult(candidate, False, None, output.splitlines()[-1] if output else "config test failed")

        process = start_xray(args.xray_bin, config_path)
        if not wait_for_port(args.bind, temp_http_port, args.warmup_timeout):
            output = collect_process_output(process)
            return ProbeResult(candidate, False, None, output or "Xray did not open the probe port")

        last_error = ""
        for url in args.test_url:
            try:
                started_at = time.monotonic()
                request_via_http_proxy(url, temp_http_port, args.bind, args.test_timeout)
                latency_ms = (time.monotonic() - started_at) * 1000
                return ProbeResult(candidate, True, latency_ms)
            except Exception as exc:
                last_error = str(exc)

        return ProbeResult(candidate, False, None, last_error or "all test URLs failed")
    except Exception as exc:
        return ProbeResult(candidate, False, None, str(exc))
    finally:
        stop_process(process)
        if config_path:
            with contextlib.suppress(OSError):
                os.unlink(config_path)


def collect_process_output(process: Optional[subprocess.Popen[str]]) -> str:
    if process is None:
        return ""
    if process.poll() is None:
        stop_process(process, timeout=1.0)
    if process.stdout is None:
        return ""
    try:
        return process.stdout.read().strip()
    except Exception:
        return ""


def probe_all(candidates: list[Candidate], args: argparse.Namespace) -> list[ProbeResult]:
    workers = max(1, min(args.concurrency, len(candidates)))
    results: list[ProbeResult] = []
    mode = "full scan" if args.full_scan else f"race, settle={args.probe_settle:.1f}s"
    log(f"Testing {len(candidates)} candidate(s) with concurrency={workers} ({mode})", "test")

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    futures = {executor.submit(probe_candidate, candidate, args) for candidate in candidates}
    pending = set(futures)
    settle_until: Optional[float] = None

    try:
        while pending:
            timeout: Optional[float] = None
            if settle_until is not None:
                timeout = max(0.0, settle_until - time.monotonic())

            done, pending = concurrent.futures.wait(
                pending,
                timeout=timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            if not done:
                break

            for future in done:
                result = future.result()
                results.append(result)
                if result.ok:
                    log(
                        f"OK #{result.candidate.index} {result.candidate.name} "
                        f"{result.latency_ms:.0f} ms",
                        "test",
                    )
                    if not args.full_scan and settle_until is None:
                        settle_until = time.monotonic() + args.probe_settle
                else:
                    log(f"FAIL #{result.candidate.index} {result.candidate.name}: {result.error}", "test")

            if not args.full_scan and settle_until is not None and time.monotonic() >= settle_until:
                break
    finally:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)

    results.sort(
        key=lambda item: (
            not item.ok,
            item.latency_ms if item.latency_ms is not None else float("inf"),
            item.candidate.index,
        )
    )
    return results


class ManagedXray:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.process: Optional[subprocess.Popen[str]] = None
        self.config_path = ""
        self.output_thread: Optional[threading.Thread] = None
        self.active_candidate: Optional[Candidate] = None

    def start(self, candidate: Candidate) -> None:
        config = build_xray_config(
            candidate=candidate,
            bind=self.args.bind,
            socks_port=self.args.socks_port,
            http_port=self.args.http_port,
            log_level=self.args.xray_log_level,
        )
        new_config_path = write_config(config)
        ok, output = run_xray_config_test(self.args.xray_bin, new_config_path)
        if not ok:
            with contextlib.suppress(OSError):
                os.unlink(new_config_path)
            raise RuntimeError(output or "Xray config test failed")

        self.stop()
        self.config_path = new_config_path
        self.active_candidate = candidate
        self.process = start_xray(self.args.xray_bin, self.config_path)
        if not wait_for_port(self.args.bind, self.args.http_port, self.args.warmup_timeout):
            output = collect_process_output(self.process)
            self.process = None
            self.active_candidate = None
            if self.config_path:
                with contextlib.suppress(OSError):
                    os.unlink(self.config_path)
                self.config_path = ""
            raise RuntimeError(output or "Xray did not open the HTTP port")

        self.output_thread = threading.Thread(
            target=self._drain_output,
            name="xray-output",
            daemon=True,
        )
        self.output_thread.start()

    def _drain_output(self) -> None:
        process = self.process
        if process is None or process.stdout is None:
            return
        for line in process.stdout:
            line = line.rstrip()
            if line:
                candidate = self.active_candidate
                if candidate is not None:
                    log(f"#{candidate.index} {candidate.name}: {line}", "traffic")
                else:
                    log(line, "traffic")

    def stop(self) -> None:
        stop_process(self.process)
        self.process = None
        self.active_candidate = None
        if self.config_path:
            with contextlib.suppress(OSError):
                os.unlink(self.config_path)
            self.config_path = ""

    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None


def pick_best(results: list[ProbeResult]) -> Optional[ProbeResult]:
    for result in results:
        if result.ok:
            return result
    return None


def health_check(args: argparse.Namespace) -> tuple[bool, str]:
    last_error = ""
    for attempt in range(args.health_retries):
        for url in args.test_url:
            try:
                request_via_http_proxy(url, args.http_port, args.bind, args.test_timeout)
                if args.log_mode == "comprehensive":
                    log(f"Health check OK via {url}", "health")
                return True, ""
            except Exception as exc:
                last_error = str(exc)
                if args.log_mode == "comprehensive":
                    log(f"Health check attempt {attempt + 1} failed via {url}: {last_error}", "health")
        if attempt + 1 < args.health_retries:
            time.sleep(args.health_retry_delay)
    return False, last_error or "all health URLs failed"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Auto-select the fastest working VLESS config and expose stable local "
            "SOCKS/HTTP proxy ports."
        )
    )
    parser.add_argument("-l", "--list", required=True, help="Text file with one VLESS URL per line")
    parser.add_argument("--xray-bin", default="xray", help="Path to the xray binary")
    parser.add_argument("--bind", default="127.0.0.1", help="Local bind address")
    parser.add_argument("--socks-port", type=int, default=10808, help="Stable SOCKS port")
    parser.add_argument("--http-port", type=int, default=10809, help="Stable HTTP proxy port")
    parser.add_argument(
        "--log-mode",
        default="minimal",
        choices=("minimal", "comprehensive"),
        help="minimal hides traffic logs; comprehensive shows colored test/health/traffic logs",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored logs")
    parser.add_argument(
        "--test-url",
        action="append",
        default=[],
        help="URL used for real-delay and health checks. Can be repeated.",
    )
    parser.add_argument("--test-timeout", type=float, default=2.5, help="Per-request timeout in seconds")
    parser.add_argument("--warmup-timeout", type=float, default=2.5, help="Xray startup wait timeout")
    parser.add_argument("--check-interval", type=float, default=15.0, help="Health check interval in seconds")
    parser.add_argument("--fail-threshold", type=int, default=3, help="Consecutive failed health rounds before switching")
    parser.add_argument("--health-retries", type=int, default=2, help="Attempts inside each health round")
    parser.add_argument("--health-retry-delay", type=float, default=0.8, help="Delay between health attempts")
    parser.add_argument("--concurrency", type=int, default=8, help="Number of candidates to test in parallel")
    parser.add_argument(
        "--probe-settle",
        type=float,
        default=0.8,
        help="After the first working candidate, keep racing for this many seconds",
    )
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help="Wait for every candidate instead of using fast race mode",
    )
    parser.add_argument(
        "--retry-interval",
        type=float,
        default=10.0,
        help="Wait time before retesting when no candidate is alive",
    )
    parser.add_argument(
        "--xray-log-level",
        default=None,
        choices=("debug", "info", "warning", "error", "none"),
        help="Xray log level. Default is warning in minimal mode and info in comprehensive mode.",
    )
    parser.add_argument(
        "--config-test-only",
        action="store_true",
        help="Only validate generated Xray configs; do not connect.",
    )

    args = parser.parse_args(argv)
    if not args.test_url:
        args.test_url = list(DEFAULT_TEST_URLS)
    if args.fail_threshold < 1:
        parser.error("--fail-threshold must be at least 1")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.health_retries < 1:
        parser.error("--health-retries must be at least 1")
    if args.probe_settle < 0:
        parser.error("--probe-settle must be zero or greater")
    if args.xray_log_level is None:
        args.xray_log_level = "info" if args.log_mode == "comprehensive" else "warning"
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    configure_logging(args.log_mode, not args.no_color)
    list_path = Path(args.list).expanduser()
    if not list_path.exists():
        log(f"Config list not found: {list_path}", "error")
        return 2

    try:
        candidates = load_candidates(list_path)
    except Exception as exc:
        log(str(exc), "error")
        return 2

    if args.config_test_only:
        failed = 0
        for candidate in candidates:
            result = probe_candidate(candidate, args, config_test_only=True)
            if result.ok:
                log(f"VALID #{candidate.index} {candidate.name}", "test")
            else:
                failed += 1
                log(f"INVALID #{candidate.index} {candidate.name}: {result.error}", "error")
        return 1 if failed else 0

    stop_event = threading.Event()

    def handle_signal(signum: int, _frame: Any) -> None:
        log(f"Received signal {signum}; shutting down", "system")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    manager = ManagedXray(args)
    active: Optional[Candidate] = None
    failures = 0

    try:
        while not stop_event.is_set():
            results = probe_all(candidates, args)
            best = pick_best(results)

            if best is None:
                if manager.running() and active is not None:
                    log(
                        f"No replacement found; keeping current #{active.index} "
                        f"{active.name} and retrying in {args.retry_interval:.0f}s",
                        "retest",
                    )
                else:
                    log(f"No live candidate found; retrying in {args.retry_interval:.0f}s", "retest")
                stop_event.wait(args.retry_interval)
                continue

            try:
                manager.start(best.candidate)
            except Exception as exc:
                log(f"Could not start #{best.candidate.index} {best.candidate.name}: {exc}", "error")
                stop_event.wait(args.retry_interval)
                continue
            active = best.candidate
            failures = 0
            log(
                f"Connected to #{active.index} {active.name}; "
                f"SOCKS={args.bind}:{args.socks_port}, HTTP={args.bind}:{args.http_port}",
                "select",
            )

            while not stop_event.wait(args.check_interval):
                if not manager.running():
                    log("Xray process exited; retesting candidates", "retest")
                    break

                ok, error = health_check(args)
                if ok:
                    failures = 0
                    continue

                failures += 1
                log(f"Health check failed ({failures}/{args.fail_threshold}): {error}", "health")
                if failures >= args.fail_threshold:
                    log("Failure threshold reached; retesting candidates", "retest")
                    break

    finally:
        manager.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
