#!/usr/bin/env python3
"""Tail an Nginx combined access log and send sanitized aggregates to Iron AI.

The sensor never sends request bodies, cookies or authorization headers.
"""

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
from urllib import error, request


COMBINED_LOG = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^]]+\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<user_agent>[^"]*)"'
)
RUNNING = True


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


def stop(*_):
    global RUNNING
    RUNNING = False


def main():
    parser = argparse.ArgumentParser(description="Iron AI sensor for Nginx combined access logs")
    parser.add_argument("--log", required=True, help="Path to the Nginx access log")
    parser.add_argument("--endpoint", required=True, help="Iron AI public HTTPS origin")
    parser.add_argument("--interval", type=int, default=10, choices=range(5, 61), metavar="5-60")
    parser.add_argument("--from-start", action="store_true", help="Read existing lines instead of following only new traffic")
    args = parser.parse_args()
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
            except error.HTTPError as exc:
                print(f"Iron AI recusou a telemetria (HTTP {exc.code})", file=sys.stderr, flush=True)
            except (error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                print(f"Iron AI indisponível: {exc}", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
