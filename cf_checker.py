#!/usr/bin/env python3
import concurrent.futures
import csv
import datetime
import ipaddress
import os
import random
import socket
import ssl
import time
from typing import Optional

import requests

CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"
RU_EGRESS_PROXY = os.getenv("RU_EGRESS_PROXY", "").strip()
SNI_HOST = os.getenv("CF_SNI_HOST", "speed.cloudflare.com").strip()
TEST_PATH = os.getenv("CF_TEST_PATH", "/__down?bytes=2000000").strip()

SAMPLES_PER_CIDR = int(os.getenv("SAMPLES_PER_CIDR", "40"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "25"))
CONNECT_TIMEOUT = float(os.getenv("CONNECT_TIMEOUT", "3.5"))
MAX_PING_MS = float(os.getenv("MAX_PING_MS", "450"))
MIN_SPEED_MBPS = float(os.getenv("MIN_SPEED_MBPS", "2.0"))
TOP_LIMIT = int(os.getenv("TOP_LIMIT", "50"))

OUTPUT_TXT = "cf_working_ips.txt"
OUTPUT_CSV = "cf_top_ips.csv"

FALLBACK_CIDRS = [
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "162.158.0.0/15",
    "188.114.96.0/20",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "173.245.48.0/20",
    "198.41.128.0/17",
]


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def fetch_cf_cidrs() -> list[str]:
    try:
        r = requests.get(CF_IPV4_URL, timeout=10)
        if r.status_code == 200 and r.text.strip():
            cidrs = [
                line.strip()
                for line in r.text.splitlines()
                if line.strip() and not line.startswith("#")
            ]
            if cidrs:
                return cidrs
    except requests.RequestException:
        pass
    return FALLBACK_CIDRS


def sample_ips(cidrs: list[str], per_cidr: int) -> list[str]:
    candidates: set[str] = set()
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        total = net.num_addresses
        if total <= 2:
            continue
        count = min(per_cidr, total - 2)
        for _ in range(count * 2):
            if len(candidates) >= len(cidrs) * per_cidr:
                break
            offset = random.randint(1, total - 2)
            ip_str = str(net.network_address + offset)
            candidates.add(ip_str)
    result = list(candidates)
    random.shuffle(result)
    return result


def parse_socks5_proxy(proxy_url: str) -> Optional[tuple[str, int, Optional[str], Optional[str]]]:
    if not proxy_url:
        return None
    from urllib.parse import urlparse

    p = urlparse(proxy_url)
    if not p.hostname or not p.port:
        return None
    return p.hostname, int(p.port), p.username, p.password


def open_tcp_via_optional_socks5(
    target_ip: str, target_port: int, timeout: float
) -> socket.socket:
    proxy = parse_socks5_proxy(RU_EGRESS_PROXY)
    if not proxy:
        return socket.create_connection((target_ip, target_port), timeout=timeout)

    p_host, p_port, p_user, p_pass = proxy
    sock = socket.create_connection((p_host, p_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        if p_user and p_pass:
            sock.sendall(b"\x05\x02\x00\x02")
            resp = sock.recv(2)
            if len(resp) < 2 or resp[0] != 5:
                raise OSError("SOCKS5 handshake failed")
            if resp[1] == 2:
                u_b = p_user.encode("utf-8")
                pw_b = p_pass.encode("utf-8")
                sock.sendall(b"\x01" + bytes([len(u_b)]) + u_b + bytes([len(pw_b)]) + pw_b)
                auth_resp = sock.recv(2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise OSError("SOCKS5 auth failed")
            elif resp[1] != 0:
                raise OSError("SOCKS5 unsupported auth")
        else:
            sock.sendall(b"\x05\x01\x00")
            resp = sock.recv(2)
            if len(resp) < 2 or resp != b"\x05\x00":
                raise OSError("SOCKS5 no-auth rejected")

        ip_bytes = socket.inet_aton(target_ip)
        req = b"\x05\x01\x00\x01" + ip_bytes + target_port.to_bytes(2, "big")
        sock.sendall(req)
        reply = sock.recv(10)
        if len(reply) < 4 or reply[1] != 0:
            raise OSError("SOCKS5 connect failed")
        return sock
    except Exception:
        sock.close()
        raise


def test_single_cf_ip(ip: str) -> Optional[tuple[str, float, float]]:
    ctx = ssl.create_default_context()
    raw_sock = None
    tls_sock = None
    try:
        t0 = time.perf_counter()
        raw_sock = open_tcp_via_optional_socks5(ip, 443, CONNECT_TIMEOUT)
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=SNI_HOST)
        tls_sock.settimeout(CONNECT_TIMEOUT)
        ping_ms = (time.perf_counter() - t0) * 1000.0
        if ping_ms > MAX_PING_MS:
            return None

        req = (
            f"GET {TEST_PATH} HTTP/1.1\r\n"
            f"Host: {SNI_HOST}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")

        dl_start = time.perf_counter()
        tls_sock.sendall(req)

        total_bytes = 0
        header_parsed = False
        buf = b""
        while True:
            chunk = tls_sock.recv(32768)
            if not chunk:
                break
            if not header_parsed:
                buf += chunk
                if b"\r\n\r\n" in buf:
                    head, body = buf.split(b"\r\n\r\n", 1)
                    first_line = head.splitlines()[0].decode("latin1", errors="ignore")
                    if " 200 " not in first_line and " 204 " not in first_line:
                        return None
                    header_parsed = True
                    total_bytes += len(body)
            else:
                total_bytes += len(chunk)

            if time.perf_counter() - dl_start >= 3.0:
                break

        elapsed = max(time.perf_counter() - dl_start, 0.001)
        if not header_parsed or total_bytes < 32768:
            return None

        speed_mbps = (total_bytes * 8.0) / (elapsed * 1_000_000.0)
        if speed_mbps < MIN_SPEED_MBPS:
            return None

        return ip, round(ping_ms, 1), round(speed_mbps, 1)
    except Exception:
        return None
    finally:
        if tls_sock:
            try:
                tls_sock.close()
            except OSError:
                pass
        elif raw_sock:
            try:
                raw_sock.close()
            except OSError:
                pass


def main() -> None:
    mode = f"via RU proxy ({RU_EGRESS_PROXY.split('@')[-1]})" if RU_EGRESS_PROXY else "direct"
    log(f"Starting Cloudflare IP check [{mode}] | SNI={SNI_HOST}")

    cidrs = fetch_cf_cidrs()
    candidates = sample_ips(cidrs, SAMPLES_PER_CIDR)
    log(f"Generated {len(candidates)} candidate IPs across {len(cidrs)} CIDRs")

    working: list[tuple[str, float, float]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_single_cf_ip, ip): ip for ip in candidates}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            res = fut.result()
            if res:
                working.append(res)
            if done % 100 == 0 or done == len(candidates):
                log(f"Progress: {done}/{len(candidates)} | Working: {len(working)}")

    # Сортируем по убыванию скорости, затем по минимальному пингу
    working.sort(key=lambda item: (-item[2], item[1]))
    top = working[:TOP_LIMIT]

    if top:
        with open(OUTPUT_TXT, "w", encoding="utf-8") as f:
            for ip, ping_ms, speed_mbps in top:
                f.write(f"{ip} # {speed_mbps:.1f} Mbps | {ping_ms:.0f} ms | @qw1lsVPN\n")

        with open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "ping_ms", "speed_mbps"])
            for ip, ping_ms, speed_mbps in top:
                writer.writerow([ip, ping_ms, speed_mbps])

        log(
            f"Saved {len(top)} clean CF IPs | Top: {top[0][0]} "
            f"({top[0][2]:.1f} Mbps, {top[0][1]:.0f} ms)"
        )
    else:
        log("No working Cloudflare IPs passed threshold.")


if __name__ == "__main__":
    main()
