#!/usr/bin/env python3
"""Tail an Nginx combined access log and send sanitized aggregates to Iron AI.

The sensor never sends request bodies, cookies or authorization headers.
"""

import argparse
from collections import defaultdict
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time
from urllib import error, request


COMBINED_LOG = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^]]+\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<user_agent>[^"]*)"'
)
RUNNING = True
APPLIED_ACTIONS = set()
AGENT_VERSION = "1.1"
MAX_BLOCK_SECONDS = 7 * 24 * 60 * 60
PROTECTED_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32",
    "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
))


def parse_line(line: str):
    match = COMBINED_LOG.match(line.strip())
    if not match:
        return None
    item = match.groupdict()
    return {
        "source_ip": item["ip"], "method": item["method"], "path": item["path"][:2048],
        "status_code": int(item["status"]), "user_agent": item["user_agent"][:512],
    }


def aggregate(lines, window_seconds: int):
    buckets = {}
    paths_by_ip = defaultdict(set)
    for line in lines:
        item = parse_line(line)
        if not item:
            continue
        paths_by_ip[item["source_ip"]].add(item["path"])
        key = (item["source_ip"], item["method"], item["path"], item["status_code"], item["user_agent"])
        if key not in buckets and len(buckets) >= 5000:
            continue
        bucket = buckets.setdefault(key, {**item, "request_count": 0, "window_seconds": window_seconds, "source": "nginx"})
        bucket["request_count"] += 1
    for item in buckets.values():
        item["distinct_paths"] = len(paths_by_ip[item["source_ip"]])
    return sorted(buckets.values(), key=lambda item: item["request_count"], reverse=True)[:100]


def send(endpoint: str, key: str, events: list[dict]):
    if not events:
        return {"received": 0, "detected": 0}
    payload = json.dumps({"events": events}, separators=(",", ":")).encode()
    req = request.Request(
        endpoint.rstrip("/") + "/api/security-monitoring/ingest",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/json", "X-Iron-AI-Sensor-Key": key, "User-Agent": "Iron-AI-Sensor/1.0"},
    )
    with request.urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode())


def firewall_available():
    return os.geteuid() == 0 and bool(shutil.which("nft") or shutil.which("iptables"))


def sensor_api(endpoint: str, key: str, path: str, method="GET", payload=None):
    data = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None
    capabilities = "host_firewall" if firewall_available() else "telemetry"
    req = request.Request(
        endpoint.rstrip("/") + "/api/security-monitoring" + path,
        data=data, method=method,
        headers={
            "Content-Type": "application/json",
            "X-Iron-AI-Sensor-Key": key,
            "X-Iron-AI-Capabilities": capabilities,
            "X-Iron-AI-Agent-Version": AGENT_VERSION,
            "User-Agent": f"Iron-AI-Sensor/{AGENT_VERSION}",
        },
    )
    with request.urlopen(req, timeout=15) as response:
        return json.loads(response.read().decode())


def _validated_public_ip(value):
    address = ipaddress.ip_address(str(value or ""))
    unsafe = any((address.is_private, address.is_loopback, address.is_link_local, address.is_reserved, address.is_multicast, address.is_unspecified))
    if unsafe or any(address in network for network in PROTECTED_NETWORKS):
        raise ValueError("IP privado, reservado ou pertencente à infraestrutura protegida")
    return address


def _run(command, *, input_text=None, check=True):
    return subprocess.run(command, input=input_text, text=True, capture_output=True, timeout=15, check=check)


def _ensure_nftables():
    listed = _run(["nft", "list", "table", "inet", "iron_ai"], check=False)
    if listed.returncode == 0:
        return
    rules = """table inet iron_ai {
  set blocked_v4 { type ipv4_addr; flags timeout; }
  set blocked_v6 { type ipv6_addr; flags timeout; }
  chain input { type filter hook input priority -10; policy accept;
    ip saddr @blocked_v4 counter drop
    ip6 saddr @blocked_v6 counter drop
  }
}
"""
    _run(["nft", "-f", "-"], input_text=rules)


def _nftables_action(operation, address, duration_seconds):
    _ensure_nftables()
    set_name = "blocked_v4" if address.version == 4 else "blocked_v6"
    existing = _run(["nft", "get", "element", "inet", "iron_ai", set_name, "{", str(address), "}"], check=False)
    if operation == "unblock_ip":
        if existing.returncode == 0:
            _run(["nft", "delete", "element", "inet", "iron_ai", set_name, "{", str(address), "}"])
        return "nftables"
    if existing.returncode == 0:
        _run(["nft", "delete", "element", "inet", "iron_ai", set_name, "{", str(address), "}"])
    _run(["nft", "add", "element", "inet", "iron_ai", set_name, "{", str(address), "timeout", f"{duration_seconds}s", "}"])
    return "nftables"


def _iptables_action(operation, address, action_id):
    binary = "iptables" if address.version == 4 else "ip6tables"
    if not shutil.which(binary):
        raise RuntimeError(f"{binary} não está instalado")
    rule = ["INPUT", "-s", str(address), "-m", "comment", "--comment", f"iron-ai-{action_id}", "-j", "DROP"]
    exists = _run([binary, "-C", *rule], check=False).returncode == 0
    if operation == "unblock_ip":
        if exists:
            _run([binary, "-D", *rule])
    elif not exists:
        _run([binary, "-I", *rule])
    return binary


def apply_firewall_action(action):
    action_id = int(action["id"])
    operation = action.get("operation")
    if operation not in {"block_ip", "unblock_ip"}:
        raise ValueError("operação de firewall não permitida")
    address = _validated_public_ip(action.get("ip"))
    duration = min(MAX_BLOCK_SECONDS, max(60, int(action.get("duration_seconds") or 24 * 60 * 60)))
    if shutil.which("nft"):
        return _nftables_action(operation, address, duration)
    return _iptables_action(operation, address, action_id)


def process_sensor_actions(endpoint, key):
    if not firewall_available():
        return
    result = sensor_api(endpoint, key, "/sensor-actions")
    for action in result.get("actions", []):
        action_id = int(action["id"])
        operation = action.get("operation")
        if operation == "block_ip" and action_id in APPLIED_ACTIONS and not action.get("report_required"):
            continue
        try:
            backend = apply_firewall_action(action)
            status_value = "released" if operation == "unblock_ip" else "executed"
            detail = "Regra restrita aplicada pelo agente Iron AI"
            if operation == "unblock_ip":
                APPLIED_ACTIONS.discard(action_id)
            else:
                APPLIED_ACTIONS.add(action_id)
        except (KeyError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            backend = None
            status_value = "failed"
            detail = str(exc)[:1000]
        if action.get("report_required"):
            sensor_api(endpoint, key, f"/sensor-actions/{action_id}/result", method="POST", payload={"status": status_value, "firewall_backend": backend, "detail": detail})


def redeem_enrollment(endpoint: str, enrollment_token: str):
    payload = json.dumps({"token": enrollment_token}).encode()
    req = request.Request(
        endpoint.rstrip("/") + "/api/security-monitoring/sensors/enroll",
        data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Iron-AI-Sensor-Installer/1.0"},
    )
    with request.urlopen(req, timeout=20) as response:
        return json.loads(response.read().decode())


def detect_nginx_log():
    candidates = ["/var/log/nginx/access.log", "/var/log/nginx/access.log.1"]
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    try:
        output = subprocess.check_output(["nginx", "-T"], stderr=subprocess.STDOUT, text=True, timeout=15)
        for line in output.splitlines():
            match = re.search(r"\baccess_log\s+([^;\s]+)", line)
            if match and Path(match.group(1)).is_file():
                return match.group(1)
    except (FileNotFoundError, subprocess.SubprocessError):
        pass
    return ""


def install_service(args):
    if os.geteuid() != 0:
        raise SystemExit("execute a instalação com sudo")
    log_path = detect_nginx_log() if args.log == "auto" else args.log
    if not log_path or not Path(log_path).is_file():
        raise SystemExit("não foi possível localizar o access.log do Nginx; informe --log manualmente")
    enrollment = redeem_enrollment(args.endpoint, args.enrollment_token)
    key = enrollment.get("key", "")
    if not key.startswith("iais_"):
        raise SystemExit("a plataforma não retornou uma chave de sensor válida")
    script_path = Path("/usr/local/libexec/iron-ai-sensor.py")
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(Path(__file__).read_text(encoding="utf-8"), encoding="utf-8")
    script_path.chmod(0o755)
    env_path = Path("/etc/iron-ai-sensor.env")
    env_path.write_text(f"IRON_AI_SENSOR_KEY={key}\n", encoding="utf-8")
    env_path.chmod(0o600)
    unit = f"""[Unit]
Description=Iron AI Nginx security sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile={env_path}
ExecStart=/usr/bin/env python3 {script_path} --log {log_path} --endpoint {args.endpoint}
Restart=always
RestartSec=10
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths={log_path}

[Install]
WantedBy=multi-user.target
"""
    unit_path = Path("/etc/systemd/system/iron-ai-sensor.service")
    unit_path.write_text(unit, encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "iron-ai-sensor.service"], check=True)
    print(f"Sensor instalado: {enrollment.get('sensor_name', 'Iron AI')} · log: {log_path}")


def stop(*_):
    global RUNNING
    RUNNING = False


def main():
    parser = argparse.ArgumentParser(description="Iron AI sensor for Nginx combined access logs")
    parser.add_argument("--log", required=True, help="Path to the Nginx access log")
    parser.add_argument("--endpoint", required=True, help="Iron AI public HTTPS origin")
    parser.add_argument("--interval", type=int, default=10, choices=range(5, 61), metavar="5-60")
    parser.add_argument("--from-start", action="store_true", help="Read existing lines instead of following only new traffic")
    parser.add_argument("--install", action="store_true", help="Install and start the sensor as a systemd service")
    parser.add_argument("--enrollment-token", default="", help="One-time token generated by the Iron AI platform")
    args = parser.parse_args()
    if args.install:
        if not args.enrollment_token.startswith("ienroll_"):
            parser.error("set --enrollment-token to the one-time token generated by the platform")
        if not args.endpoint.startswith("https://") and not args.endpoint.startswith("http://localhost"):
            parser.error("--endpoint must use HTTPS (HTTP is accepted only for localhost)")
        install_service(args)
        return
    key = os.getenv("IRON_AI_SENSOR_KEY", "")
    if not key.startswith("iais_"):
        parser.error("set IRON_AI_SENSOR_KEY to the key shown once by the platform")
    if not args.endpoint.startswith("https://") and not args.endpoint.startswith("http://localhost"):
        parser.error("--endpoint must use HTTPS (HTTP is accepted only for localhost)")
    path = Path(args.log)
    if not path.is_file():
        parser.error("the access log does not exist or is not a file")
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        if not args.from_start:
            handle.seek(0, 2)
        while RUNNING:
            started = time.monotonic()
            lines = []
            while RUNNING and time.monotonic() - started < args.interval:
                line = handle.readline()
                if line:
                    lines.append(line)
                else:
                    time.sleep(0.25)
            try:
                result = send(args.endpoint, key, aggregate(lines, args.interval))
                if result.get("detected"):
                    print(f"Iron AI: {result['detected']} incidente(s) detectado(s)", flush=True)
                process_sensor_actions(args.endpoint, key)
            except error.HTTPError as exc:
                print(f"Iron AI recusou a telemetria (HTTP {exc.code})", file=sys.stderr, flush=True)
            except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                print(f"Iron AI indisponível: {exc}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
