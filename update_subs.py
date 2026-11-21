import base64
import json
import os
import re
import signal
import socket
import statistics
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SOURCES_URL = (
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/"
    "refs/heads/main/sources.txt"
)
BRAND_TAG = "@qw1lsVPN"
SUB_FILE = os.path.join(BASE_DIR, "sub.txt")
README_FILE = os.path.join(BASE_DIR, "README.md")

LATENCY_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]

SPEEDTEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes=5242880",
    "https://raw.githubusercontent.com/BitDoctor/speed-test-file/refs/heads/master/5mb.txt",
]

SUPPORTED_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")

MAX_TCP_PING_MS = 3000
MAX_LATENCY_MS = 2500
TCP_PING_TIMEOUT = 2.0
HTTP_TIMEOUT = 6.0
SPEEDTEST_MAX_SECONDS = 3.5
MAX_CANDIDATES = 1500
SOURCE_FETCH_WORKERS = 12
CHECK_WORKERS = 12
MAX_RUNTIME_SECONDS = 300

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


def log(msg: str) -> None:
    print(msg, flush=True)


def country_code_to_flag(cc: str) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌍"
    cc = cc.upper()
    return chr(ord(cc[0]) + 0x1F1A5) + chr(ord(cc[1]) + 0x1F1A5)


def format_country_from_code(cc: str, raw_name: str = "") -> tuple[str, str]:
    cc = (cc or "").upper().strip()
    if cc == "UK":
        cc = "GB"
    if cc in COUNTRY_MAP:
        return COUNTRY_MAP[cc]
    clean_name = (raw_name or "").strip()
    if clean_name in COUNTRY_RU_TRANSLATION:
        clean_name = COUNTRY_RU_TRANSLATION[clean_name]
    if len(cc) == 2 and cc.isalpha():
        return country_code_to_flag(cc), clean_name or cc
    return "🌍", clean_name or "Европа"


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port: int, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.25)
                s.connect(("127.0.0.1", port))
                return True
        except OSError:
            time.sleep(0.06)
    return False


def tcp_ping(host: str, port: int, timeout: float = TCP_PING_TIMEOUT) -> float | None:
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return (time.perf_counter() - start) * 1000.0
    except OSError:
        return None


def _b64_decode_str(s: str) -> str:
    cleaned = "".join(s.strip().split())
    cleaned = cleaned.replace("-", "+").replace("_", "/")
    pad = len(cleaned) % 4
    if pad:
        cleaned += "=" * (4 - pad)
    return base64.b64decode(cleaned, validate=False).decode("utf-8", errors="ignore")


def maybe_b64_decode(text: str) -> str:
    if not text or "://" in text:
        return text
    try:
        decoded = _b64_decode_str(text)
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return text


def detect_operators(raw_meta: str) -> str:
    lower = raw_meta.lower()
    if "все оператор" in lower or "all" in lower:
        return "все операторы"
    found = []
    for key, label in OPERATORS_MAP.items():
        if re.search(rf"(?<![a-zа-я0-9]){re.escape(key)}(?![a-zа-я0-9])", lower):
            if label not in found:
                found.append(label)
    return ", ".join(found) if found else "все операторы"


def is_whitelist_entry(raw_meta: str) -> bool:
    lower = raw_meta.lower()
    return any(kw in lower for kw in WHITELIST_KEYWORDS)


def clean_uri(uri: str) -> str:
    return uri.split("#", 1)[0].strip()


def _parse_ss_parts(base: str) -> tuple[str, str, str, int] | None:
    body = base[5:]
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        host_part = hostport.split("/", 1)[0].split("?", 1)[0]
        if ":" not in host_part:
            return None
        host, port_s = host_part.rsplit(":", 1)
        port = int(port_s)
        try:
            decoded_user = _b64_decode_str(userinfo)
            if ":" in decoded_user:
                method, password = decoded_user.split(":", 1)
                return method, password, host, port
        except Exception:
            pass
        if ":" in unquote(userinfo):
            method, password = unquote(userinfo).split(":", 1)
            return method, password, host, port
        return None
    else:
        try:
            decoded = _b64_decode_str(body)
            if "@" not in decoded:
                return None
            creds, hostport = decoded.rsplit("@", 1)
            method, password = creds.split(":", 1)
            host, port_s = hostport.rsplit(":", 1)
            return method, password, host, int(port_s)
        except Exception:
            return None


def extract_host_port(uri: str) -> tuple[str, int] | None:
    base = clean_uri(uri)
    if len(base) > 8192:
        return None
    try:
        p = urlparse(base)
        if p.scheme in ("vless", "trojan"):
            if not p.hostname:
                return None
            return p.hostname, int(p.port or 443)
        if p.scheme == "vmess":
            data = json.loads(_b64_decode_str(base[8:]))
            add = data.get("add")
            if not add:
                return None
            return str(add), int(data.get("port", 443))
        if p.scheme == "ss":
            parsed = _parse_ss_parts(base)
            if not parsed:
                return None
            _, _, host, port = parsed
            return host, port
    except Exception:
        return None
    return None


def _build_stream_settings(query: dict, fallback_host: str) -> dict:
    network = (query.get("type", ["tcp"])[0] or "tcp").lower()
    security = (query.get("security", ["none"])[0] or "none").lower()
    sni = unquote(query.get("sni", query.get("host", [fallback_host]))[0] or fallback_host)
    fp = unquote(query.get("fp", [""])[0] or "chrome")
    path_hdr = unquote(query.get("path", ["/"])[0] or "/")

    stream: dict = {"network": network}

    if security == "reality":
        pbk = unquote(query.get("pbk", [""])[0])
        if not pbk:
            return {}
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "show": False,
            "fingerprint": fp,
            "serverName": sni,
            "publicKey": pbk,
            "shortId": unquote(query.get("sid", [""])[0]),
            "spiderX": unquote(query.get("spx", ["/"])[0] or "/"),
        }
    elif security == "tls":
        tls_cfg: dict = {
            "serverName": sni,
            "fingerprint": fp,
            "allowInsecure": True,
        }
        if alpn_raw := unquote(query.get("alpn", [""])[0]):
            tls_cfg["alpn"] = [x.strip() for x in alpn_raw.split(",") if x.strip()]
        stream["security"] = "tls"
        stream["tlsSettings"] = tls_cfg

    host_hdr = unquote(query.get("host", [sni])[0] or sni)

    if network == "ws":
        stream["wsSettings"] = {
            "path": path_hdr,
            "headers": {"Host": host_hdr} if host_hdr else {},
        }
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": unquote(query.get("serviceName", [""])[0]),
            "multiMode": query.get("mode", [""])[0] == "multi",
        }
    elif network in ("h2", "http"):
        stream["network"] = "h2"
        stream["httpSettings"] = {
            "path": path_hdr,
            "host": [host_hdr] if host_hdr else [],
        }
    elif network in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        xhttp_obj: dict = {
            "path": path_hdr,
            "host": host_hdr,
        }
        if "mode" in query:
            xhttp_obj["mode"] = query["mode"][0]
        stream["xhttpSettings"] = xhttp_obj

    return stream


def uri_to_outbound(uri: str) -> dict | None:
    base = clean_uri(uri)
    try:
        if base.startswith("vless://"):
            p = urlparse(base)
            if not p.hostname or not p.username:
                return None
            query = parse_qs(p.query)
            stream = _build_stream_settings(query, p.hostname)
            if not stream:
                return None
            user: dict = {
                "id": unquote(p.username),
                "encryption": query.get("encryption", ["none"])[0] or "none",
            }
            if flow := query.get("flow", [""])[0]:
                user["flow"] = flow
            return {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": p.hostname,
                            "port": int(p.port or 443),
                            "users": [user],
                        }
                    ]
                },
                "streamSettings": stream,
            }

        if base.startswith("vmess://"):
            data = json.loads(_b64_decode_str(base[8:]))
            add = data.get("add")
            uid = data.get("id")
            if not add or not uid:
                return None
            net = str(data.get("net", "tcp")).lower()
            path_val = str(data.get("path", "/") or "/")
            stream: dict = {"network": net}
            sni_val = data.get("sni") or data.get("host", "")
            if str(data.get("tls", "")).lower() == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {
                    "serverName": sni_val,
                    "fingerprint": "chrome",
                    "allowInsecure": True,
                }
            if net == "ws":
                stream["wsSettings"] = {
                    "path": path_val,
                    "headers": {"Host": data.get("host", "")},
                }
            elif net == "grpc":
                stream["grpcSettings"] = {"serviceName": data.get("path", "")}
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": str(add),
                            "port": int(data.get("port", 443)),
                            "users": [
                                {
                                    "id": str(uid),
                                    "alterId": int(data.get("aid", 0) or 0),
                                    "security": "auto",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": stream,
            }

        if base.startswith("trojan://"):
            p = urlparse(base)
            if not p.hostname or not p.username:
                return None
            query = parse_qs(p.query)
            if "security" not in query:
                query["security"] = ["tls"]
            stream = _build_stream_settings(query, p.hostname)
            if not stream:
                return None
            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": p.hostname,
                            "port": int(p.port or 443),
                            "password": unquote(p.username),
                        }
                    ]
                },
                "streamSettings": stream,
            }

        if base.startswith("ss://"):
            parsed = _parse_ss_parts(base)
            if not parsed:
                return None
            method, password, host, port = parsed
            return {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": host,
                            "port": port,
                            "method": method,
                            "password": password,
                        }
                    ]
                },
            }
    except Exception:
        return None
    return None


def _spawn_xray(outbound: dict, socks_port: int):
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [outbound],
    }
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            cfg_path = f.name
        proc = subprocess.Popen(
            ["xray", "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        return proc, cfg_path
    except OSError:
        return None, None


def _stop_xray(proc, cfg_path):
    if proc:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            pass
    if cfg_path and os.path.exists(cfg_path):
        try:
            os.unlink(cfg_path)
        except OSError:
            pass


def resolve_country(host: str, proxies: dict | None = None) -> tuple[str, str]:
    if host in _country_cache:
        return _country_cache[host]

    if proxies:
        for url, cc_key, name_key in (
            ("https://api.country.is/", "country", ""),
            ("https://ipwho.is/", "country_code", "country"),
        ):
            try:
                r = requests.get(url, proxies=proxies, timeout=2.5)
                if r.ok:
                    data = r.json()
                    cc = data.get(cc_key, "")
                    if cc:
                        res = format_country_from_code(
                            cc,
                            data.get(name_key, "") if name_key else "",
                        )
                        _country_cache[host] = res
                        return res
            except Exception:
                continue

    try:
        ip = socket.gethostbyname(host)
        if ip in _country_cache:
            _country_cache[host] = _country_cache[ip]
            return _country_cache[host]

        providers = [
            (
                f"https://api.country.is/{ip}",
                lambda d: (d.get("country", ""), ""),
            ),
            (
                f"https://ipwho.is/{ip}",
                lambda d: (d.get("country_code", ""), d.get("country", "")),
            ),
            (
                f"http://ip-api.com/json/{ip}?fields=status,countryCode,country",
                lambda d: (d.get("countryCode", ""), d.get("country", ""))
                if d.get("status") == "success"
                else ("", ""),
            ),
        ]
        for url, extractor in providers:
            try:
                r = requests.get(url, timeout=2.5)
                if r.ok:
                    cc, cname = extractor(r.json())
                    if cc:
                        res = format_country_from_code(cc, cname)
                        _country_cache[host] = res
                        _country_cache[ip] = res
                        return res
            except Exception:
                continue
    except Exception:
        pass

    return ("🌍", "Европа")


def measure_traffic_mbps_and_ms(
    proxies: dict, headers: dict
) -> tuple[float, float | None]:
    """Проверяет живой трафик через прокси: возвращает (mbps, best_ms)."""
    latencies: list[float] = []
    for url in LATENCY_URLS:
        try:
            t0 = time.perf_counter()
            r = requests.get(url, proxies=proxies, headers=headers, timeout=(3.0, HTTP_TIMEOUT))
            ms = (time.perf_counter() - t0) * 1000.0
            if r.status_code in (200, 204):
                latencies.append(ms)
                break
        except requests.RequestException:
            continue

    if not latencies:
        return 0.0, None

    best_ms = min(latencies)
    if best_ms > MAX_LATENCY_MS:
        return 0.0, best_ms

    speeds: list[float] = []
    for url in SPEEDTEST_URLS:
        try:
            downloaded = 0
            start = time.perf_counter()
            with requests.get(
                url,
                proxies=proxies,
                headers=headers,
                timeout=(3.0, HTTP_TIMEOUT),
                stream=True,
            ) as r:
                if r.status_code != 200:
                    continue
                for chunk in r.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    elapsed = time.perf_counter() - start
                    if elapsed >= 0.2 and downloaded > 0:
                        speeds.append((downloaded * 8.0 / (1024 * 1024)) / elapsed)
                    if elapsed >= SPEEDTEST_MAX_SECONDS:
                        break
            if speeds:
                return statistics.median(speeds), best_ms
        except requests.RequestException:
            continue

    # Пропуск трафика по generate_204 есть, но спидтест не успел — оставляем как живой узел
    return 0.0, best_ms


def evaluate_config(uri: str, meta: str) -> tuple[bool, float, float, tuple[str, str], str]:
    hp = extract_host_port(uri)
    if not hp:
        return False, 0.0, 9999.0, ("🌍", "Европа"), "bad_uri"
    host, port = hp
    if host in ("0.0.0.0", "127.0.0.1", "localhost") or port <= 0:
        return False, 0.0, 9999.0, ("🌍", "Европа"), "bad_host"

    ping = tcp_ping(host, port, timeout=TCP_PING_TIMEOUT)
    if ping is None or ping > MAX_TCP_PING_MS:
        return False, 0.0, 9999.0, ("🌍", "Европа"), "tcp_fail"

    outbound = uri_to_outbound(uri)
    if not outbound:
        return False, 0.0, 9999.0, ("🌍", "Европа"), "bad_outbound"

    socks_port = get_free_port()
    proc, cfg_path = _spawn_xray(outbound, socks_port)
    if not proc:
        return False, 0.0, 9999.0, ("🌍", "Европа"), "xray_spawn_fail"

    try:
        if not wait_for_port(socks_port):
            return False, 0.0, 9999.0, ("🌍", "Европа"), "xray_port_fail"

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/131.0.0.0 Safari/537.36"
            )
        }

        mbps, ms = measure_traffic_mbps_and_ms(proxies, headers)
        if ms is None:
            return False, 0.0, 9999.0, ("🌍", "Европа"), "no_traffic_ping"
        if ms > MAX_LATENCY_MS:
            return False, 0.0, ms, ("🌍", "Европа"), "high_ms"

        country_info = resolve_country(host, proxies=proxies)
        return True, mbps, ms, country_info, "ok"
    finally:
        _stop_xray(proc, cfg_path)


def _fetch_single_sub(url: str, line_meta: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    try:
        sub_r = requests.get(url, timeout=6)
        if sub_r.ok:
            sub_txt = maybe_b64_decode(sub_r.text)
            for sline in sub_txt.splitlines():
                sline = sline.strip()
                if sline.startswith(SUPPORTED_SCHEMES):
                    frag = unquote(sline.split("#", 1)[1]) if "#" in sline else ""
                    combined_meta = f"{line_meta} {frag}".strip()
                    found.append((sline, combined_meta))
    except Exception:
        pass
    return found


def collect_candidates_from_sources() -> list[tuple[str, str]]:
    log(f"Fetching sources from {SOURCES_URL}...")
    resp = requests.get(SOURCES_URL, timeout=12)
    resp.raise_for_status()
    raw_text = maybe_b64_decode(resp.text)

    candidates: list[tuple[str, str]] = []
    sub_tasks: list[tuple[str, str]] = []
    seen_base: set[str] = set()
    current_group_meta = ""

    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#") and "://" not in line:
            current_group_meta = line.lstrip("#").strip()
            continue

        line_meta = current_group_meta
        uri_part = line
        if " | " in line and "://" in line:
            parts = line.split(" | ", 1)
            uri_part = parts[0].strip()
            line_meta = f"{current_group_meta} {parts[1].strip()}".strip()

        if uri_part.startswith(("http://", "https://")):
            sub_tasks.append((uri_part, line_meta))
        elif uri_part.startswith(SUPPORTED_SCHEMES):
            frag = unquote(uri_part.split("#", 1)[1]) if "#" in uri_part else ""
            combined_meta = f"{line_meta} {frag}".strip()
            base_uri = clean_uri(uri_part)
            if base_uri not in seen_base:
                seen_base.add(base_uri)
                candidates.append((uri_part, combined_meta))

    if sub_tasks:
        with ThreadPoolExecutor(max_workers=SOURCE_FETCH_WORKERS) as pool:
            futs = [pool.submit(_fetch_single_sub, u, m) for u, m in sub_tasks]
            for fut in as_completed(futs):
                for sline, combined_meta in fut.result():
                    base_uri = clean_uri(sline)
                    if base_uri not in seen_base:
                        seen_base.add(base_uri)
                        candidates.append((sline, combined_meta))

    log(f"Collected {len(candidates)} unique candidates (from {len(sub_tasks)} sub URLs).")
    return candidates


def format_server_name(
    uri: str, meta: str, country_info: tuple[str, str], mbps: float, ms: float
) -> str:
    frag = unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    combined = f"{frag} {meta}".strip()
    speed_part = f"{mbps:.1f}Mbps" if mbps > 0 else "live"
    metrics = f"[{speed_part} | {int(round(ms))}ms]"
    if is_whitelist_entry(combined):
        ops = detect_operators(combined)
        return f"🇪🇺 white list ({ops}) {metrics} {BRAND_TAG}"
    flag, country_name = country_info
    flag = flag or "🌍"
    country_name = country_name or "Европа"
    return f"{flag} {country_name} {metrics} {BRAND_TAG}"


def update_readme(count: int) -> None:
    if not os.path.exists(README_FILE):
        return
    with open(README_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    badge_line = f"Рабочих серверов в подписке: **{count}**"
    if re.search(r"Рабочих серверов в подписке:\s*\*\*\d+\*\*", content):
        content = re.sub(
            r"Рабочих серверов в подписке:\s*\*\*\d+\*\*",
            badge_line,
            content,
        )
    else:
        content = content.rstrip() + f"\n\n{badge_line}\n"
    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(content)


def main() -> None:
    start_ts = time.time()
    log(f"Writing to {SUB_FILE} | max_ms={MAX_LATENCY_MS}, max_candidates={MAX_CANDIDATES}")
    candidates = collect_candidates_from_sources()[:MAX_CANDIDATES]
    working: list[tuple[str, str, float, float]] = []
    reasons: dict[str, int] = {}

    def worker(item: tuple[str, str]):
        uri, meta = item
        ok, mbps, ms, country_info, reason = evaluate_config(uri, meta)
        return uri, meta, ok, mbps, ms, country_info, reason

    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        futures = [pool.submit(worker, c) for c in candidates]
        for idx, fut in enumerate(as_completed(futures), start=1):
            if time.time() - start_ts > MAX_RUNTIME_SECONDS:
                log("Reached MAX_RUNTIME_SECONDS limit, stopping.")
                break
            uri, meta, ok, mbps, ms, country_info, reason = fut.result()
            reasons[reason] = reasons.get(reason, 0) + 1
            hp = extract_host_port(uri)
            target_str = f"{hp[0]}:{hp[1]}" if hp else uri[:40]
            if ok:
                title = format_server_name(uri, meta, country_info, mbps, ms)
                working.append((clean_uri(uri), title, mbps, ms))
                log(f"[{idx}/{len(candidates)}] OK {mbps:.1f}Mbps / {ms:.0f}ms {target_str} -> {title}")
            else:
                log(f"[{idx}/{len(candidates)}] FAIL ({reason}) {target_str}")

    log(f"Stats: {reasons}")

    if not working:
        log("0 servers passed traffic check; keeping existing sub.txt so subscription is not wiped.")
        return

    # Сначала узлы с измеренной скоростью по убыванию, затем по наименьшей задержке (ms)
    working.sort(key=lambda x: (-x[2], x[3]))

    header_lines = [
        f"#profile-title: {BRAND_TAG}",
        "#profile-update-interval: 2",
    ]
    final_links: list[str] = []
    for idx, (base_uri, title, mbps, ms) in enumerate(working):
        final_title = f"{title} ⚡" if idx == 0 else title
        if idx == 0:
            log(f"Top server: {final_title} ({mbps:.1f} Mbps, {ms:.0f} ms)")
        final_links.append(f"{base_uri}#{quote(final_title)}")

    with open(SUB_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(header_lines + final_links) + "\n")

    update_readme(len(final_links))
    log(f"Saved {len(final_links)} servers to {SUB_FILE}.")


if __name__ == "__main__":
    main()
