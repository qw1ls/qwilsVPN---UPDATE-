import base64
import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

BASE_DIR = Path(__file__).resolve().parent
SOURCES_URL = (
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/"
    "refs/heads/main/sources.txt"
)
BRAND_TAG = "@qw1lsVPN"
SUB_FILE = BASE_DIR / "sub.txt"
README_FILE = BASE_DIR / "README.md"

MAX_PING_MS = 2500
TCP_TIMEOUT = 1.3
TEST_TIMEOUT = 5
SPEEDTEST_MAX_SECONDS = 2.0
SOCKS_PORT_MIN = 20000
PORT_POOL_SIZE = 128
CONCURRENT_CHECKS = 10
MAX_CANDIDATES = 2000
MAX_RUNTIME_SECONDS = 320

TEST_URLS = [
    "https://www.google.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]

SPEEDTEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes=524288",
    "https://raw.githubusercontent.com/BitDoctor/speed-test-file/refs/heads/master/5mb.txt",
]

URI_REGEX = re.compile(r'(?:vless|vmess|trojan|ss)://[^\s"\'<>`]+', re.IGNORECASE)

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

COUNTRY_RU_TRANSLATION = {
    "Russia": "Россия",
    "Germany": "Германия",
    "Netherlands": "Нидерланды",
    "Finland": "Финляндия",
    "Sweden": "Швеция",
    "France": "Франция",
    "United Kingdom": "Великобритания",
    "United States": "США",
    "Poland": "Польша",
    "Lithuania": "Литва",
    "Latvia": "Латвия",
    "Estonia": "Эстония",
    "Switzerland": "Швейцария",
    "Austria": "Австрия",
    "Czechia": "Чехия",
    "Czech Republic": "Чехия",
    "Turkey": "Турция",
    "Turkiye": "Турция",
    "Kazakhstan": "Казахстан",
    "United Arab Emirates": "ОАЭ",
    "Singapore": "Сингапур",
    "Japan": "Япония",
    "Canada": "Канада",
    "Hong Kong": "Гонконг",
    "Moldova": "Молдова",
    "Bulgaria": "Болгария",
    "Romania": "Румыния",
}

OPERATORS_MAP = {
    "mts": "МТС",
    "мтс": "МТС",
    "megafon": "Мегафон",
    "мегафон": "Мегафон",
    "beeline": "Билайн",
    "билайн": "Билайн",
    "t2": "T2",
    "tele2": "T2",
    "теле2": "T2",
    "yota": "Yota",
    "йота": "Yota",
}

WHITELIST_KEYWORDS = (
    "white list",
    "whitelist",
    "white_list",
    "белый список",
    "белые списки",
    "mobile",
    "cidr",
    "lte",
    "4g",
    "5g",
    "white",
    "wl",
)

_country_cache: dict[str, tuple[str, str]] = {}
_debug_printed = 0


def log(msg: str) -> None:
    print(msg, flush=True)


def find_xray() -> str | None:
    name = "xray.exe" if sys.platform == "win32" else "xray"
    found = shutil.which(name)
    if found:
        return found
    for base in [BASE_DIR, Path("."), Path.home() / "xray", Path("/usr/local/bin")]:
        exe = base / name
        if exe.exists():
            return str(exe)
    return None


def _make_port_pool() -> Queue[int]:
    q: Queue[int] = Queue()
    for i in range(PORT_POOL_SIZE):
        q.put(SOCKS_PORT_MIN + i)
    return q


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
    items: list[str] = list(URI_REGEX.findall(text))
    if "://" not in text:
        try:
            decoded = _b64_decode(text)
            if "://" in decoded:
                items.extend(URI_REGEX.findall(decoded))
        except Exception:
            pass
    unique: list[str] = []
    seen: set[str] = set()
    for u in items:
        u = u.strip()
        if u and u not in seen:
            seen.add(u)
            unique.append(u)
    return unique


def _parse_ss(base: str) -> tuple[str, str, str, int] | None:
    body = base[5:]
    try:
        if "@" in body:
            userinfo, hostport = body.rsplit("@", 1)
            host_part = hostport.split("/", 1)[0].split("?", 1)[0]
            host, port_s = host_part.rsplit(":", 1)
            port = int(port_s)
            try:
                dec = _b64_decode(userinfo)
                if ":" in dec:
                    m, p = dec.split(":", 1)
                    return m, p, host, port
            except Exception:
                pass
            raw_u = unquote(userinfo)
            if ":" in raw_u:
                m, p = raw_u.split(":", 1)
                return m, p, host, port
            return None
        dec = _b64_decode(body)
        if "@" not in dec:
            return None
        creds, hostport = dec.rsplit("@", 1)
        m, p = creds.split(":", 1)
        host, port_s = hostport.rsplit(":", 1)
        return m, p, host, int(port_s)
    except Exception:
        return None


def extract_host_port(uri: str) -> tuple[str, int] | None:
    base = clean_uri(uri)
    try:
        if base.startswith(("vless://", "trojan://")):
            parsed = urlparse(base)
            if not parsed.hostname:
                return None
            return parsed.hostname.lower(), int(parsed.port or 443)
        if base.startswith("vmess://"):
            data = json.loads(_b64_decode(base[8:]))
            addr = data.get("add") or data.get("address") or ""
            if not addr:
                return None
            return str(addr).lower(), int(data.get("port", 443))
        if base.startswith("ss://"):
            sp = _parse_ss(base)
            if not sp:
                return None
            return sp[2].lower(), sp[3]
    except Exception:
        return None
    return None


def tcp_reachable(host: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _is_valid_reality_pbk(pbk: str) -> bool:
    if not pbk:
        return False
    try:
        s = pbk.strip().replace("-", "+").replace("_", "/")
        pad = len(s) % 4
        if pad:
            s += "=" * (4 - pad)
        raw = base64.b64decode(s, validate=False)
        return len(raw) == 32
    except Exception:
        return False


def _stream_settings(
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
        stream["security"] = "reality"
        real_cfg: dict = {
            "serverName": sni or host or "www.google.com",
            "fingerprint": fp or "chrome",
            "publicKey": pbk.strip(),
            "shortId": sid.strip(),
        }
        if spx.strip():
            real_cfg["spiderX"] = spx.strip()
        stream["realitySettings"] = real_cfg
    elif sec == "tls":
        tls_cfg: dict = {
            "serverName": sni or host,
            "fingerprint": fp or "chrome",
            "allowInsecure": True,
        }
        if alpn:
            tls_cfg["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls_cfg
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
            uid = unquote(uid_raw)
            if ":" in host_port:
                host, port_s = host_port.rsplit(":", 1)
                port = int(port_s)
            else:
                host, port = host_port, 443
            if not uid or not host:
                return None
            q = parse_qs(parsed.query)
            get = lambda k, d="": unquote((q.get(k) or [d])[0]).strip()
            stream = _stream_settings(
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
            flow = get("flow")
            user: dict = {"id": uid, "encryption": get("encryption", "none") or "none"}
            if flow:
                user["flow"] = flow
            return {
                "protocol": "vless",
                "tag": "proxy",
                "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                "streamSettings": stream,
            }

        if base.startswith("vmess://"):
            data = json.loads(_b64_decode(base[8:]))
            addr = str(data.get("add") or data.get("address") or "").strip()
            uid = str(data.get("id") or data.get("uuid") or "").strip()
            if not addr or not uid:
                return None
            port = int(data.get("port", 443))
            tls_flag = str(data.get("tls", "")).strip().lower() in ("1", "true", "tls", "yes")
            sec = "tls" if tls_flag else "none"
            sni = str(data.get("sni") or data.get("host") or addr).strip()
            host_h = str(data.get("host") or sni).strip()
            stream = _stream_settings(
                net=str(data.get("net") or "tcp"),
                security=sec,
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
            pwd = unquote(pwd_raw)
            if ":" in host_port:
                host, port_s = host_port.rsplit(":", 1)
                port = int(port_s)
            else:
                host, port = host_port, 443
            if not pwd or not host:
                return None
            q = parse_qs(parsed.query)
            get = lambda k, d="": unquote((q.get(k) or [d])[0]).strip()
            stream = _stream_settings(
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
                srv["flow"] = flow
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


def country_flag(cc: str) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌍"
    cc = cc.upper()
    return chr(ord(cc[0]) + 0x1F1A5) + chr(ord(cc[1]) + 0x1F1A5)


def resolve_country(host: str) -> tuple[str, str]:
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
            f"https://api.country.is/{ip}",
        ):
            try:
                r = requests.get(url, timeout=2.0)
                if not r.ok:
                    continue
                d = r.json()
                cc = (d.get("countryCode") or d.get("country_code") or d.get("country") or "").upper()
                cname = (d.get("country") or "").strip()
                if cc == "UK":
                    cc = "GB"
                if cc in COUNTRY_MAP:
                    res = COUNTRY_MAP[cc]
                    _country_cache[host] = res
                    return res
                if cname in COUNTRY_RU_TRANSLATION:
                    res = (country_flag(cc), COUNTRY_RU_TRANSLATION[cname])
                    _country_cache[host] = res
                    return res
                if len(cc) == 2 and cc.isalpha():
                    res = (country_flag(cc), cname or cc)
                    _country_cache[host] = res
                    return res
            except Exception:
                continue
    except Exception:
        pass
    res = ("🌍", "Европа")
    _country_cache[host] = res
    return res


def detect_operators(raw_meta: str) -> str:
    lower = raw_meta.lower()
    if "все оператор" in lower or "all" in lower:
        return "все операторы"
    found: list[str] = []
    for k, label in OPERATORS_MAP.items():
        if re.search(rf"(?<![a-zа-я0-9]){re.escape(k)}(?![a-zа-я0-9])", lower):
            if label not in found:
                found.append(label)
    return ", ".join(found) if found else "все операторы"


def is_whitelist(raw_meta: str) -> bool:
    lower = raw_meta.lower()
    return any(kw in lower for kw in WHITELIST_KEYWORDS)


def format_title(uri: str, meta: str, country: tuple[str, str], mbps: float, ms: float) -> str:
    frag = unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    combined = f"{frag} {meta}".strip()
    speed_str = f"{mbps:.1f}Mbps" if mbps > 0 else "LIVE"
    metrics = f"[{speed_str} | {int(round(ms))}ms]"
    if is_whitelist(combined):
        return f"🇪🇺 white list ({detect_operators(combined)}) {metrics} {BRAND_TAG}"
    flag, name = country
    return f"{flag or '🌍'} {name or 'Европа'} {metrics} {BRAND_TAG}"


def measure_mbps(proxies: dict) -> float:
    speeds: list[float] = []
    for url in SPEEDTEST_URLS:
        try:
            downloaded = 0
            start = time.perf_counter()
            with requests.get(url, proxies=proxies, timeout=TEST_TIMEOUT, stream=True) as r:
                if r.status_code != 200:
                    continue
                for chunk in r.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    elapsed = time.perf_counter() - start
                    if elapsed >= 0.1 and downloaded > 0:
                        speeds.append((downloaded * 8.0 / (1024 * 1024)) / elapsed)
                    if elapsed >= SPEEDTEST_MAX_SECONDS:
                        break
            if speeds:
                return statistics.median(speeds)
        except Exception:
            continue
    return 0.0


def run_xray_and_test(
    xray_exe: str,
    outbound: dict,
    socks_port: int,
    timeout: int = TEST_TIMEOUT,
) -> tuple[bool, float, float, str]:
    global _debug_printed
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    fd, cfg_path = tempfile.mkstemp(suffix=".json")
    proc = None
    try:
        cfg_data = build_xray_config(outbound, socks_port)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg_data, f)
        fd = -1

        proc = subprocess.Popen(
            [xray_exe, "run", "-config", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=creationflags,
        )
        time.sleep(0.5)

        if proc.poll() is not None:
            err_raw = b""
            if proc.stderr:
                try:
                    err_raw = proc.stderr.read() or b""
                except Exception:
                    pass
            err_txt = err_raw.decode("utf-8", errors="ignore").strip()
            if _debug_printed < 5:
                _debug_printed += 1
                log(f"[DEBUG XRAY EXIT] {err_txt[:220] or 'exit code ' + str(proc.returncode)}")
            return False, 0.0, -1.0, "xray_exited"

        proxy_url = f"socks5://127.0.0.1:{socks_port}"
        proxies = {"http": proxy_url, "https": proxy_url}

        ping_ms: float | None = None
        last_err = ""
        for test_url in TEST_URLS:
            t0 = time.perf_counter()
            try:
                r = requests.get(test_url, proxies=proxies, timeout=timeout)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if r.status_code in (200, 204):
                    ping_ms = elapsed_ms
                    break
                last_err = f"http_{r.status_code}"
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                continue

        if ping_ms is None:
            if _debug_printed < 5:
                _debug_printed += 1
                log(f"[DEBUG REQ FAIL] {last_err[:220]}")
            return False, 0.0, -1.0, "no_traffic"

        if ping_ms > MAX_PING_MS:
            return False, 0.0, ping_ms, "high_ping"

        mbps = measure_mbps(proxies)
        return True, mbps, ping_ms, "ok"
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                proc.kill()
            except Exception:
                pass
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def collect_sources() -> list[tuple[str, str]]:
    log(f"Fetching sources from {SOURCES_URL}...")
    resp = requests.get(SOURCES_URL, timeout=20)
    resp.raise_for_status()
    raw = resp.text.strip()
    if "://" not in raw and not raw.startswith(("{", "[")):
        try:
            raw = _b64_decode(raw)
        except Exception:
            pass

    candidates: list[tuple[str, str]] = []
    sub_urls: list[tuple[str, str]] = []
    seen_hp: set[tuple[str, int]] = set()
    group_meta = ""

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#") and "://" not in line:
            group_meta = line.lstrip("#").strip()
            continue
        meta = group_meta
        part = line
        if " | " in line and "://" in line:
            part, extra = line.split(" | ", 1)
            part = part.strip()
            meta = f"{group_meta} {extra.strip()}".strip()
        if part.startswith(("http://", "https://")):
            sub_urls.append((part, meta))
        else:
            for u in extract_uris(part):
                hp = extract_host_port(u)
                if hp and hp not in seen_hp:
                    seen_hp.add(hp)
                    frag = unquote(u.split("#", 1)[1]) if "#" in u else ""
                    candidates.append((u, f"{meta} {frag}".strip()))

    def fetch_sub(item: tuple[str, str]) -> list[tuple[str, str]]:
        url, m = item
        out: list[tuple[str, str]] = []
        try:
            r = requests.get(url, timeout=8, headers={"User-Agent": "v2ray-checker/1.0"})
            if r.ok:
                for u in extract_uris(r.text):
                    frag = unquote(u.split("#", 1)[1]) if "#" in u else ""
                    out.append((u, f"{m} {frag}".strip()))
        except Exception:
            pass
        return out

    if sub_urls:
        with ThreadPoolExecutor(max_workers=10) as pool:
            for fut in as_completed([pool.submit(fetch_sub, s) for s in sub_urls]):
                for u, m in fut.result():
                    hp = extract_host_port(u)
                    if hp and hp not in seen_hp:
                        seen_hp.add(hp)
                        candidates.append((u, m))

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
    port_pool = _make_port_pool()
    working: list[tuple[str, str, float, float]] = []
    stats: dict[str, int] = {}

    def check_one(item: tuple[str, str]):
        uri, meta = item
        hp = extract_host_port(uri)
        if not hp:
            return False, uri, meta, 0.0, -1.0, ("🌍", "Европа"), "bad_uri"
        host, port = hp
        outbound = uri_to_outbound(uri)
        if not outbound:
            return False, uri, meta, 0.0, -1.0, ("🌍", "Европа"), "bad_outbound"
        if not tcp_reachable(host, port, timeout=TCP_TIMEOUT):
            return False, uri, meta, 0.0, -1.0, ("🌍", "Европа"), "tcp_closed"
        p = port_pool.get()
        try:
            ok, mbps, ms, reason = run_xray_and_test(xray_exe, outbound, p, timeout=TEST_TIMEOUT)
            country = resolve_country(host) if ok else ("🌍", "Европа")
            return ok, uri, meta, mbps, ms, country, reason
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
                ok, uri, meta, mbps, ms, country, reason = fut.result()
            except Exception:
                ok, uri, meta, mbps, ms, country, reason = False, "", "", 0.0, -1.0, ("🌍", "Европа"), "error"
            stats[reason] = stats.get(reason, 0) + 1
            if ok:
                title = format_title(uri, meta, country, mbps, ms)
                working.append((clean_uri(uri), title, mbps, ms))
                log(f"[{idx}/{len(candidates)}] OK {mbps:.1f}Mbps / {ms:.0f}ms -> {title}")
            else:
                log(f"[{idx}/{len(candidates)}] FAIL ({reason})")
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    log(f"Stats: {stats}")

    working.sort(key=lambda x: (-x[2], x[3]))
    now_str = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    header = [
        f"#profile-title: {BRAND_TAG}",
        "#profile-update-interval: 2",
        f"#announce: Обновлено: {now_str} | Серверов: {len(working)}",
    ]
    links: list[str] = []
    for i, (base_uri, title, _, _) in enumerate(working):
        final_title = f"{title} ⚡" if i == 0 else title
        links.append(f"{base_uri}#{quote(final_title)}")

    SUB_FILE.write_text("\n".join(header + links) + "\n", encoding="utf-8")
    update_readme(len(links))
    log(f"Saved {len(links)} working servers to {SUB_FILE}.")


if __name__ == "__main__":
    main()
