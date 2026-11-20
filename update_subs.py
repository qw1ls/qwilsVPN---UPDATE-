import base64
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

SOURCES_URL = (
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/"
    "refs/heads/main/sources.txt"
)
BRAND_TAG = "@qw1lsVPN"
SUB_FILE = "sub.txt"
README_FILE = "README.md"

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://telegram.org",
    "https://www.youtube.com/generate_204",
]

SPEEDTEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes=5242880",
    "https://raw.githubusercontent.com/BitDoctor/speed-test-file/refs/heads/master/5mb.txt",
]

MIN_SUCCESS = 2
MAX_TCP_PING_MS = 2200
TCP_PING_TIMEOUT = 1.8
TIMEOUT_PER_URL = 8
SPEEDTEST_MAX_SECONDS = 4.0
MIN_SPEED_MBPS = 0.1
MAX_CANDIDATES = 250
CHECK_WORKERS = 10
MAX_RUNTIME_SECONDS = 240

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
        return "🌐"
    cc = cc.upper()
    return chr(ord(cc[0]) + 0x1F1A5) + chr(ord(cc[1]) + 0x1F1A5)


def format_country_from_code(cc: str, fallback_name: str = "") -> tuple[str, str]:
    cc = (cc or "").upper().strip()
    if cc in COUNTRY_MAP:
        return COUNTRY_MAP[cc]
    if len(cc) == 2 and cc.isalpha():
        return country_code_to_flag(cc), fallback_name or cc
    return "🌐", fallback_name or "Сервер"


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
            time.sleep(0.08)
    return False


def tcp_ping(host: str, port: int, timeout: float = TCP_PING_TIMEOUT) -> float | None:
    try:
        start = time.perf_counter()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return (time.perf_counter() - start) * 1000.0
    except OSError:
        return None


def maybe_b64_decode(text: str) -> str:
    cleaned = "".join(text.strip().split())
    if not cleaned or "://" in text:
        return text
    pad = len(cleaned) % 4
    if pad:
        cleaned += "=" * (4 - pad)
    try:
        decoded = base64.b64decode(cleaned, validate=False).decode("utf-8", errors="ignore")
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
            b64 = base[8:]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            add = data.get("add")
            if not add:
                return None
            return str(add), int(data.get("port", 443))
    except Exception:
        return None
    return None


def get_security_type(uri: str) -> str:
    base = clean_uri(uri)
    try:
        p = urlparse(base)
        if p.scheme in ("vless", "trojan"):
            q = parse_qs(p.query)
            sec = (q.get("security", ["none"])[0] or "none").lower()
            if p.scheme == "trojan" and sec == "none":
                return "tls"
            return sec
        if p.scheme == "vmess":
            b64 = base[8:]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            return str(data.get("tls", "none")).lower()
    except Exception:
        pass
    return "none"


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
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": sni,
            "fingerprint": fp,
            "allowInsecure": False,
        }

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
            b64 = base[8:]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
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
                    "allowInsecure": False,
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


def resolve_country_fast(host: str, proxies: dict | None = None) -> tuple[str, str]:
    """Определяет страну и флаг с кэшем, чтобы серверы стабильно переименовывались."""
    if host in _country_cache:
        return _country_cache[host]

    # 1. Быстрая проверка по IP/хосту через ip-api / country.is
    try:
        ip = socket.gethostbyname(host)
        if ip in _country_cache:
            _country_cache[host] = _country_cache[ip]
            return _country_cache[host]

        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,countryCode,country",
            timeout=2.5,
        )
        if r.ok:
            data = r.json()
            if data.get("status") == "success":
                res = format_country_from_code(
                    data.get("countryCode", ""),
                    data.get("country", ""),
                )
                _country_cache[host] = res
                _country_cache[ip] = res
                return res
    except Exception:
        pass

    # 2. Фолбэк через сам прокси (реальный выходной IP)
    if proxies:
        try:
            r = requests.get("https://api.country.is/", proxies=proxies, timeout=4)
            if r.ok:
                cc = r.json().get("country", "")
                if cc:
                    res = format_country_from_code(cc)
                    _country_cache[host] = res
                    return res
        except Exception:
            pass

    return ("🌐", "Сервер")


def measure_speed_mbps(proxies: dict, headers: dict) -> float:
    for url in SPEEDTEST_URLS:
        try:
            downloaded = 0
            start = time.perf_counter()
            with requests.get(
                url,
                proxies=proxies,
                headers=headers,
                timeout=(4.0, TIMEOUT_PER_URL),
                stream=True,
            ) as r:
                if r.status_code != 200:
                    continue
                for chunk in r.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    downloaded += len(chunk)
                    if time.perf_counter() - start >= SPEEDTEST_MAX_SECONDS:
                        break
            elapsed = time.perf_counter() - start
            if elapsed >= 0.2 and downloaded >= 16384:
                return (downloaded * 8.0 / (1024 * 1024)) / elapsed
        except requests.RequestException:
            continue
    return 0.0


def evaluate_config(uri: str, meta: str) -> tuple[bool, float, tuple[str, str]]:
    hp = extract_host_port(uri)
    if not hp:
        return False, 0.0, ("🌐", "Сервер")
    host, port = hp
    if host in ("0.0.0.0", "127.0.0.1", "localhost") or port <= 0:
        return False, 0.0, ("🌐", "Сервер")

    is_lte = is_whitelist_entry(f"{uri} {meta}")
    max_ping = 7000 if is_lte else MAX_TCP_PING_MS
    ping = tcp_ping(host, port, timeout=2.5 if is_lte else TCP_PING_TIMEOUT)
    if ping is None or ping > max_ping:
        return False, 0.0, ("🌐", "Сервер")

    outbound = uri_to_outbound(uri)
    if not outbound:
        return False, 0.0, ("🌐", "Сервер")

    socks_port = get_free_port()
    proc, cfg_path = _spawn_xray(outbound, socks_port)
    if not proc:
        return False, 0.0, ("🌐", "Сервер")

    try:
        if not wait_for_port(socks_port):
            return False, 0.0, ("🌐", "Сервер")

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

        success = 0
        url_timeout = 14 if is_lte else TIMEOUT_PER_URL
        for url in TEST_URLS:
            try:
                r = requests.get(
                    url,
                    proxies=proxies,
                    headers=headers,
                    timeout=(4.0, url_timeout),
                )
                if r.status_code in (200, 204):
                    if r.status_code == 204 or len(r.content or b"") > 0:
                        success += 1
                        if success >= MIN_SUCCESS:
                            break
            except requests.RequestException:
                continue

        if success < MIN_SUCCESS:
            return False, 0.0, ("🌐", "Сервер")

        speed = measure_speed_mbps(proxies, headers)
        min_speed = 0.02 if is_lte else MIN_SPEED_MBPS
        if speed < min_speed:
            return False, 0.0, ("🌐", "Сервер")

        country_info = resolve_country_fast(host, proxies=proxies)
        return True, speed, country_info
    finally:
        _stop_xray(proc, cfg_path)


def collect_candidates_from_sources() -> list[tuple[str, str]]:
    log(f"Fetching sources from {SOURCES_URL}...")
    resp = requests.get(SOURCES_URL, timeout=10)
    resp.raise_for_status()
    raw_text = maybe_b64_decode(resp.text)

    candidates: list[tuple[str, str]] = []
    seen_base: set[str] = set()
    current_group_meta = ""
    schemes = ("vless://", "vmess://", "trojan://")

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
            try:
                sub_r = requests.get(uri_part, timeout=6)
                if sub_r.ok:
                    sub_txt = maybe_b64_decode(sub_r.text)
                    for sline in sub_txt.splitlines():
                        sline = sline.strip()
                        if sline.startswith(schemes):
                            frag = unquote(sline.split("#", 1)[1]) if "#" in sline else ""
                            combined_meta = f"{line_meta} {frag}".strip()
                            base_uri = clean_uri(sline)
                            if base_uri not in seen_base:
                                seen_base.add(base_uri)
                                candidates.append((sline, combined_meta))
            except Exception:
                continue
        elif uri_part.startswith(schemes):
            frag = unquote(uri_part.split("#", 1)[1]) if "#" in uri_part else ""
            combined_meta = f"{line_meta} {frag}".strip()
            base_uri = clean_uri(uri_part)
            if base_uri not in seen_base:
                seen_base.add(base_uri)
                candidates.append((uri_part, combined_meta))

    candidates.sort(
        key=lambda item: (
            0 if is_whitelist_entry(f"{item[0]} {item[1]}") else (1 if get_security_type(item[0]) == "reality" else 2)
        )
    )
    log(f"Collected {len(candidates)} unique candidates.")
    return candidates


def format_server_name(uri: str, meta: str, country_info: tuple[str, str]) -> str:
    frag = unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    combined = f"{frag} {meta}".strip()
    if is_whitelist_entry(combined):
        ops = detect_operators(combined)
        return f"🇪🇺 white list ({ops})"
    flag, country_name = country_info
    return f"{flag} {country_name} {BRAND_TAG}"


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
    candidates = collect_candidates_from_sources()[:MAX_CANDIDATES]
    working: list[tuple[str, str, float]] = []

    def worker(item: tuple[str, str]):
        uri, meta = item
        ok, speed, country_info = evaluate_config(uri, meta)
        return uri, meta, ok, speed, country_info

    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        futures = [pool.submit(worker, c) for c in candidates]
        for idx, fut in enumerate(as_completed(futures), start=1):
            if time.time() - start_ts > MAX_RUNTIME_SECONDS:
                log("Reached MAX_RUNTIME_SECONDS limit, stopping.")
                break
            uri, meta, ok, speed, country_info = fut.result()
            hp = extract_host_port(uri)
            target_str = f"{hp[0]}:{hp[1]}" if hp else uri[:40]
            if ok:
                title = format_server_name(uri, meta, country_info)
                working.append((clean_uri(uri), title, speed))
                log(f"[{idx}/{len(candidates)}] OK ({speed:.2f} Mbps) {target_str} -> {title}")
            else:
                log(f"[{idx}/{len(candidates)}] FAIL {target_str}")

    working.sort(key=lambda x: x[2], reverse=True)

    header_lines = [
        f"#profile-title: {BRAND_TAG}",
        "#profile-update-interval: 2",
    ]
    final_links: list[str] = []
    for idx, (base_uri, title, speed) in enumerate(working):
        final_title = f"{title} ⚡" if idx == 0 else title
        if idx == 0:
            log(f"Fastest server: {final_title} ({speed:.2f} Mbps)")
        final_links.append(f"{base_uri}#{quote(final_title)}")

    with open(SUB_FILE, "w", encoding="utf-8") as f:
        if final_links:
            f.write("\n".join(header_lines + final_links) + "\n")
        else:
            f.write("")

    update_readme(len(final_links))
    log(f"Done. Active servers written to {SUB_FILE}: {len(final_links)}")


if __name__ == "__main__":
    main()
