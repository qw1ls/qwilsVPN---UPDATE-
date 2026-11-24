#!/usr/bin/env python3
"""
Update VPN subscription (single output file: sub.txt).
"""

from __future__ import annotations

import base64
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from queue import Queue
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

BASE_DIR = Path(__file__).resolve().parent
SOURCES_URL = (
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/"
    "refs/heads/main/sources.txt"
)
SUB_FILE = BASE_DIR / "sub.txt"
README_FILE = BASE_DIR / "README.md"
BRAND_TAG = "@qw1lsVPN"

TEST_URLS = [
    "https://www.google.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://ya.ru",
]

TEST_TIMEOUT = 7
MAX_PING_MS = 3500
SOCKS_PORT_MIN = 20000
PORT_POOL_SIZE = 64
CONCURRENT_CHECKS = 8
MAX_CANDIDATES = 1800
MAX_RUNTIME_SECONDS = 320

URI_REGEX = re.compile(r'(?:vless|vmess|trojan|ss)://[^\s"\'<>`]+', re.IGNORECASE)
REALITY_PBK_RE = re.compile(r"^[A-Za-z0-9_-]{43,44}$")
REALITY_SID_RE = re.compile(r"^[0-9a-fA-F]{0,32}$")

SS_XRAY_ALLOWED_METHODS = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "none",
    "plain",
}

INVALID_HOSTS = {"", "127.0.0.1", "0.0.0.0", "localhost", "::1"}

COUNTRY_MAP = {
    "RU": ("🇷🇺", "Россия"),
    "DE": ("🇩🇪", "Германия"),
    "NL": ("🇳🇱", "Нидерланды"),
    "FI": ("🇫🇮", "Финляндия"),
    "SE": ("🇸🇪", "Швеция"),
    "FR": ("🇫🇷", "Франция"),
    "GB": ("🇬🇧", "Великобритания"),
    "UK": ("🇬🇧", "Великобритания"),
    "US": ("🇺🇸", "США"),
    "PL": ("🇵🇱", "Польша"),
    "LT": ("🇱🇹", "Литва"),
    "LV": ("🇱🇻", "Латвия"),
    "EE": ("🇪🇪", "Эстония"),
    "CH": ("🇨🇭", "Швейцария"),
    "AT": ("🇦🇹", "Австрия"),
    "CZ": ("🇨🇿", "Чехия"),
    "TR": ("🇹🇷", "Турция"),
    "KZ": ("🇰🇿", "Казахстан"),
    "AE": ("🇦🇪", "ОАЭ"),
    "SG": ("🇸🇬", "Сингапур"),
    "JP": ("🇯🇵", "Япония"),
    "CA": ("🇨🇦", "Канада"),
    "HK": ("🇭🇰", "Гонконг"),
    "MD": ("🇲🇩", "Молдова"),
    "BG": ("🇧🇬", "Болгария"),
    "RO": ("🇷🇴", "Румыния"),
}

_country_cache: dict[str, tuple[str, str]] = {}


def log(msg: str) -> None:
    print(msg, flush=True)


def find_xray() -> str | None:
    exe_name = "xray.exe" if sys.platform == "win32" else "xray"
    found = shutil.which(exe_name)
    if found:
        return found
    for folder in (BASE_DIR, Path("."), Path.home() / "xray", Path("/usr/local/bin")):
        candidate = folder / exe_name
        if candidate.is_file():
            return str(candidate)
    return None


def _b64_decode(s: str) -> str:
    cleaned = "".join(s.strip().split()).replace("-", "+").replace("_", "/")
    pad = len(cleaned) % 4
    if pad:
        cleaned += "=" * (4 - pad)
    return base64.b64decode(cleaned, validate=False).decode("utf-8", errors="ignore")


def clean_uri(uri: str) -> str:
    return uri.split("#", 1)[0].strip()


def extract_uris(text: str) -> list[str]:
    if not text:
        return []
    found: list[str] = list(URI_REGEX.findall(text))
    if "://" not in text:
        try:
            dec = _b64_decode(text)
            if "://" in dec:
                found.extend(URI_REGEX.findall(dec))
        except Exception:
            pass
    out: list[str] = []
    seen: set[str] = set()
    for u in found:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _normalize_ss_method(method: str) -> str:
    m = (method or "").strip().lower()
    if m == "chacha20-poly1305":
        return "chacha20-ietf-poly1305"
    if m == "xchacha20-poly1305":
        return "xchacha20-ietf-poly1305"
    return m


def _parse_ss(base: str) -> tuple[str, str, str, int] | None:
    body = base[5:]
    try:
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            host_part = hostport.split("/", 1)[0].split("?", 1)[0].strip()
            if host_part.startswith("[") and "]:" in host_part:
                host, port_s = host_part[1:].rsplit("]:", 1)
            else:
                host, port_s = host_part.rsplit(":", 1)
            port = int(port_s)
            host = host.strip().lower()
            try:
                dec = _b64_decode(userinfo)
                if ":" in dec:
                    m, p = dec.split(":", 1)
                    return _normalize_ss_method(m), p, host, port
            except Exception:
                pass
            raw_u = unquote(userinfo)
            if ":" in raw_u:
                m, p = raw_u.split(":", 1)
                return _normalize_ss_method(m), p, host, port
            return None

        dec = _b64_decode(body)
        if "@" not in dec:
            return None
        creds, hostport = dec.rsplit("@", 1)
        m, p = creds.split(":", 1)
        host_part = hostport.split("/", 1)[0].split("?", 1)[0].strip()
        host, port_s = host_part.rsplit(":", 1)
        return _normalize_ss_method(m), p, host.strip().lower(), int(port_s)
    except Exception:
        return None


def extract_host_port(uri: str) -> tuple[str, int] | None:
    base = clean_uri(uri)
    try:
        if base.startswith(("vless://", "trojan://")):
            parsed = urlparse(base)
            host = (parsed.hostname or "").strip().lower()
            if host in INVALID_HOSTS:
                return None
            return host, int(parsed.port or 443)
        if base.startswith("vmess://"):
            data = json.loads(_b64_decode(base[8:]))
            addr = str(data.get("add") or data.get("address") or "").strip().lower()
            if addr in INVALID_HOSTS:
                return None
            return addr, int(data.get("port", 443))
        if base.startswith("ss://"):
            sp = _parse_ss(base)
            if not sp or sp[2] in INVALID_HOSTS:
                return None
            return sp[2], sp[3]
    except Exception:
        return None
    return None


def _is_valid_reality_pbk(pbk: str) -> bool:
    s = (pbk or "").strip()
    if not REALITY_PBK_RE.match(s):
        return False
    try:
        b64 = s.replace("-", "+").replace("_", "/")
        pad = len(b64) % 4
        if pad:
            b64 += "=" * (4 - pad)
        return len(base64.b64decode(b64, validate=False)) == 32
    except Exception:
        return False


def _build_stream(
    net: str = "tcp",
    security: str = "none",
    sni: str = "",
    fp: str = "chrome",
    alpn: str = "",
    path: str = "/",
    host: str = "",
    pbk: str = "",
    sid: str = "",
    spx: str = "",
    grpc_service: str = "",
) -> dict | None:
    ns = net.lower() if net.lower() in ("tcp", "ws", "grpc", "http", "h2") else "tcp"
    sec = security.lower()
    if sec == "none" and pbk:
        sec = "reality"

    stream: dict = {"network": ns}
    if sec == "reality":
        if not _is_valid_reality_pbk(pbk):
            return None
        sid_clean = (sid or "").strip()
        if sid_clean and not REALITY_SID_RE.match(sid_clean):
            return None
        stream["security"] = "reality"
        rc: dict = {
            "serverName": sni or host or "www.google.com",
            "fingerprint": fp or "chrome",
            "publicKey": pbk.strip(),
            "shortId": sid_clean,
        }
        if spx.strip():
            rc["spiderX"] = spx.strip()
        stream["realitySettings"] = rc
    elif sec == "tls":
        tc: dict = {
            "serverName": sni or host,
            "fingerprint": fp or "chrome",
            "allowInsecure": True,
        }
        if alpn:
            tc["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        stream["security"] = "tls"
        stream["tlsSettings"] = tc
    else:
        stream["security"] = "none"

    if ns == "ws":
        stream["wsSettings"] = {
            "path": path or "/",
            "headers": {"Host": host or sni} if (host or sni) else {},
        }
    elif ns == "grpc":
        stream["grpcSettings"] = {"serviceName": grpc_service or ""}
    elif ns in ("http", "h2"):
        stream["network"] = "h2"
        stream["httpSettings"] = {
            "path": path or "/",
            "host": [host or sni] if (host or sni) else [],
        }

    return stream


def uri_to_outbound(uri: str) -> dict | None:
    base = clean_uri(uri)
    try:
        if base.startswith("vless://"):
            parsed = urlparse(base)
            if "@" not in parsed.netloc:
                return None
            uid_raw, host_port = parsed.netloc.rsplit("@", 1)
            uid = unquote(uid_raw).strip()
            if ":" in host_port:
                host, port_s = host_port.rsplit(":", 1)
                port = int(port_s)
            else:
                host, port = host_port, 443
            host = host.strip().lower()
            if not uid or host in INVALID_HOSTS:
                return None
            q = parse_qs(parsed.query)
            get = lambda k, d="": unquote((q.get(k) or [d])[0]).strip()
            stream = _build_stream(
                net=get("type", "tcp"),
                security=get("security", "none"),
                sni=get("sni") or get("host") or host,
                fp=get("fp", "chrome"),
                alpn=get("alpn", ""),
                path=get("path", "/"),
                host=get("host") or get("sni") or host,
                pbk=get("pbk") or get("publicKey"),
                sid=get("sid") or get("shortId"),
                spx=get("spx") or get("spiderX"),
                grpc_service=get("serviceName"),
            )
            if stream is None:
                return None
            user: dict = {"id": uid, "encryption": get("encryption", "none") or "none"}
            flow = get("flow")
            if flow in ("xtls-rprx-vision", "xtls-rprx-visi"):
                user["flow"] = "xtls-rprx-vision"
            return {
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                "streamSettings": stream,
            }

        if base.startswith("vmess://"):
            data = json.loads(_b64_decode(base[8:]))
            addr = str(data.get("add") or data.get("address") or "").strip().lower()
            uid = str(data.get("id") or data.get("uuid") or "").strip()
            if addr in INVALID_HOSTS or not uid:
                return None
            port = int(data.get("port", 443))
            tls_on = str(data.get("tls", "")).strip().lower() in ("1", "true", "tls", "yes")
            sni = str(data.get("sni") or data.get("host") or addr).strip()
            host_h = str(data.get("host") or sni).strip()
            stream = _build_stream(
                net=str(data.get("net") or "tcp"),
                security="tls" if tls_on else "none",
                sni=sni,
                fp=str(data.get("fp") or "chrome"),
                alpn=str(data.get("alpn") or ""),
                path=str(data.get("path") or "/"),
                host=host_h,
            )
            if stream is None:
                return None
            return {
                "protocol": "vmess",
                "tag": "proxy",
                "settings": {
                    "vnext": [
                        {
                            "address": addr,
                            "port": port,
                            "users": [
                                {
                                    "id": uid,
                                    "alterId": int(data.get("aid", 0) or 0),
                                    "security": str(data.get("scy") or "auto"),
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream,
            }

        if base.startswith("trojan://"):
            parsed = urlparse(base)
            if "@" not in parsed.netloc:
                return None
            pwd_raw, host_port = parsed.netloc.rsplit("@", 1)
            pwd = unquote(pwd_raw).strip()
            if ":" in host_port:
                host, port_s = host_port.rsplit(":", 1)
                port = int(port_s)
            else:
                host, port = host_port, 443
            host = host.strip().lower()
            if not pwd or host in INVALID_HOSTS:
                return None
            q = parse_qs(parsed.query)
            get = lambda k, d="": unquote((q.get(k) or [d])[0]).strip()
            stream = _build_stream(
                net=get("type", "tcp"),
                security=get("security", "tls"),
                sni=get("sni") or get("host") or host,
                fp=get("fp", "chrome"),
                alpn=get("alpn", ""),
                path=get("path", "/"),
                host=get("host") or get("sni") or host,
                pbk=get("pbk") or get("publicKey"),
                sid=get("sid") or get("shortId"),
                spx=get("spx") or get("spiderX"),
                grpc_service=get("serviceName"),
            )
            if stream is None:
                return None
            srv: dict = {"address": host, "port": port, "password": pwd}
            if flow := get("flow"):
                if flow in ("xtls-rprx-vision", "xtls-rprx-visi"):
                    srv["flow"] = "xtls-rprx-vision"
            return {
                "protocol": "trojan",
                "tag": "proxy",
                "settings": {"servers": [srv]},
                "streamSettings": stream,
            }

        if base.startswith("ss://"):
            sp = _parse_ss(base)
            if not sp:
                return None
            method, password, host, port = sp
            if host in INVALID_HOSTS or method not in SS_XRAY_ALLOWED_METHODS:
                return None
            return {
                "protocol": "shadowsocks",
                "tag": "proxy",
                "settings": {
                    "servers": [
                        {"address": host, "port": port, "method": method, "password": password}
                    ]
                },
            }
    except Exception:
        return None
    return None


def build_xray_config(outbound: dict, socks_port: int) -> dict:
    return {
        "log": {"loglevel": "error"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            outbound,
            {"protocol": "freedom", "tag": "direct"},
        ],
    }


def _flag_from_code(cc: str) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌍"
    cc = cc.upper()
    return chr(ord(cc[0]) + 0x1F1A5) + chr(ord(cc[1]) + 0x1F1A5)


def resolve_country(host: str) -> tuple[str, str]:
    if not host or host in INVALID_HOSTS:
        return ("🌍", "Сервер")
    if host in _country_cache:
        return _country_cache[host]
    try:
        ip = host
        try:
            socket.inet_aton(host)
        except OSError:
            ip = socket.gethostbyname(host)
        for url in (
            f"http://ip-api.com/json/{ip}?fields=status,countryCode,country",
            f"https://ipwho.is/{ip}",
        ):
            try:
                r = requests.get(url, timeout=2.0)
                if not r.ok:
                    continue
                d = r.json()
                cc = (d.get("countryCode") or d.get("country_code") or "").upper()
                if cc == "UK":
                    cc = "GB"
                if cc in COUNTRY_MAP:
                    res = COUNTRY_MAP[cc]
                    _country_cache[host] = res
                    return res
                if len(cc) == 2 and cc.isalpha():
                    cname = (d.get("country") or cc).strip()
                    res = (_flag_from_code(cc), cname)
                    _country_cache[host] = res
                    return res
            except Exception:
                continue
    except Exception:
        pass
    res = ("🌍", "Сервер")
    _country_cache[host] = res
    return res


def format_title(country: tuple[str, str], ms: float) -> str:
    flag, name = country
    ms_int = max(1, int(round(ms)))
    return f"{flag} {name} [{ms_int}ms] {BRAND_TAG}"


def run_xray_and_test(
    xray_exe: str,
    outbound: dict,
    socks_port: int,
    timeout: int = TEST_TIMEOUT,
) -> tuple[bool, float, str]:
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    fd, cfg_path = tempfile.mkstemp(suffix=".json")
    proc = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(build_xray_config(outbound, socks_port), f)
        fd = -1

        proc = subprocess.Popen(
            [xray_exe, "run", "-config", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        time.sleep(0.75)
        if proc.poll() is not None:
            return False, -1.0, "xray_exited"

        proxy_url = f"socks5://127.0.0.1:{socks_port}"
        proxies = {"http": proxy_url, "https": proxy_url}
        req_timeout = max(1.5, float(timeout) - 1.0)

        for test_url in TEST_URLS:
            t0 = time.perf_counter()
            try:
                r = requests.get(test_url, proxies=proxies, timeout=req_timeout)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if r.status_code in (200, 204, 301, 302):
                    if elapsed_ms > MAX_PING_MS:
                        return False, elapsed_ms, "high_ping"
                    return True, elapsed_ms, "ok"
            except Exception:
                continue

        return False, -1.0, "no_traffic"
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception:
                pass
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def collect_sources() -> list[str]:
    log(f"Fetching sources from {SOURCES_URL}...")
    resp = requests.get(SOURCES_URL, timeout=20)
    resp.raise_for_status()
    raw = resp.text.strip()
    if "://" not in raw and not raw.startswith(("{", "[")):
        try:
            raw = _b64_decode(raw)
        except Exception:
            pass

    candidates: list[str] = []
    sub_urls: list[str] = []
    seen_hp: set[tuple[str, int]] = set()

    for line in raw.splitlines():
        line = line.strip()
        if not line or (line.startswith("#") and "://" not in line):
            continue
        part = line.split(" | ", 1)[0].strip() if (" | " in line and "://" in line) else line
        if part.startswith(("http://", "https://")):
            sub_urls.append(part)
        else:
            for u in extract_uris(part):
                hp = extract_host_port(u)
                if hp and hp not in seen_hp:
                    seen_hp.add(hp)
                    candidates.append(u)

    def fetch_sub(url: str) -> list[str]:
        try:
            r = requests.get(url, timeout=8, headers={"User-Agent": "v2ray-checker/1.0"})
            if r.ok:
                return extract_uris(r.text)
        except Exception:
            pass
        return []

    if sub_urls:
        with ThreadPoolExecutor(max_workers=10) as pool:
            for fut in as_completed([pool.submit(fetch_sub, u) for u in sub_urls]):
                for u in fut.result():
                    hp = extract_host_port(u)
                    if hp and hp not in seen_hp:
                        seen_hp.add(hp)
                        candidates.append(u)

    log(f"Collected {len(candidates)} unique servers from {len(sub_urls)} subscriptions.")
    return candidates[:MAX_CANDIDATES]


def update_readme(count: int) -> None:
    if not README_FILE.exists():
        return
    content = README_FILE.read_text(encoding="utf-8")
    line = f"Рабочих серверов в подписке: **{count}**"
    if re.search(r"Рабочих серверов в подписке:\s*\*\*\d+\*\*", content):
        content = re.sub(r"Рабочих серверов в подписке:\s*\*\*\d+\*\*", line, content)
    else:
        content = content.rstrip() + f"\n\n{line}\n"
    README_FILE.write_text(content, encoding="utf-8")


def main() -> None:
    xray_exe = find_xray()
    if not xray_exe:
        log("[ERROR] xray binary not found.")
        sys.exit(1)

    start_ts = time.time()
    candidates = collect_sources()
    port_pool: Queue[int] = Queue()
    for i in range(PORT_POOL_SIZE):
        port_pool.put(SOCKS_PORT_MIN + i)

    working: list[tuple[str, float]] = []
    stats: dict[str, int] = {}

    def check_one(uri: str):
        hp = extract_host_port(uri)
        if not hp:
            return False, uri, -1.0, ("🌍", "Сервер"), "bad_uri"
        host, _ = hp
        outbound = uri_to_outbound(uri)
        if not outbound:
            return False, uri, -1.0, ("🌍", "Сервер"), "bad_outbound"
        p = port_pool.get()
        try:
            ok, ms, reason = run_xray_and_test(xray_exe, outbound, p, timeout=TEST_TIMEOUT)
            country = resolve_country(host) if ok else ("🌍", "Сервер")
            return ok, uri, ms, country, reason
        finally:
            port_pool.put(p)

    pool = ThreadPoolExecutor(max_workers=CONCURRENT_CHECKS)
    try:
        futures = [pool.submit(check_one, c) for c in candidates]
        for idx, fut in enumerate(as_completed(futures), start=1):
            if time.time() - start_ts > MAX_RUNTIME_SECONDS:
                log("Runtime limit reached, finishing...")
                for f in futures:
                    f.cancel()
                break
            try:
                ok, uri, ms, country, reason = fut.result()
            except Exception:
                ok, uri, ms, country, reason = False, "", -1.0, ("🌍", "Сервер"), "error"
            stats[reason] = stats.get(reason, 0) + 1
            if ok:
                title = format_title(country, ms)
                working.append((f"{clean_uri(uri)}#{quote(title)}", ms))
                log(f"[{idx}/{len(candidates)}] OK {ms:.0f}ms -> {title}")
            else:
                log(f"[{idx}/{len(candidates)}] FAIL ({reason})")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    working.sort(key=lambda x: x[1])
    lines = [link for link, _ in working]
    SUB_FILE.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    update_readme(len(lines))
    log(f"Stats: {stats}")
    log(f"Saved {len(lines)} working servers to {SUB_FILE}.")


if __name__ == "__main__":
    main()
