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

SOURCES_URL = (
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/"
    "refs/heads/main/sources.txt"
)
BRAND_TAG = "@qw1lsVPN"
SUB_FILE = "sub.txt"
README_FILE = "README.md"

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://www.youtube.com/generate_204",
    "https://telegram.org",
    "https://www.instagram.com",
]
SPEEDTEST_URL = (
    "https://raw.githubusercontent.com/BitDoctor/speed-test-file/"
    "refs/heads/master/5mb.txt"
)

MIN_SUCCESS = 2
TIMEOUT_PER_URL = 5
MAX_TCP_PING_MS = 1500
TCP_PING_TIMEOUT = 1.2
SPEEDTEST_TIMEOUT = 6
MAX_CANDIDATES = 120
CHECK_WORKERS = 6
MAX_RUNTIME_SECONDS = 180

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
    "white",
    "wl",
)


def log(msg: str) -> None:
    print(msg, flush=True)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port(port: int, timeout: float = 2.5) -> bool:
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


def tcp_ping(host: str, port: int) -> float | None:
    try:
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TCP_PING_TIMEOUT)
            sock.connect((host, port))
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


def _build_stream_settings(query: dict, fallback_host: str) -> dict:
    network = (query.get("type", ["tcp"])[0] or "tcp").lower()
    security = (query.get("security", ["none"])[0] or "none").lower()
    sni = unquote(query.get("sni", query.get("host", [fallback_host]))[0])
    fp = unquote(query.get("fp", [""])[0])
    stream: dict = {"network": network}

    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "show": False,
            "fingerprint": fp or "chrome",
            "serverName": sni,
            "publicKey": unquote(query.get("pbk", [""])[0]),
            "shortId": unquote(query.get("sid", [""])[0]),
            "spiderX": unquote(query.get("spx", [""])[0]),
        }
    elif security == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "allowInsecure": False,
        }

    host_hdr = unquote(query.get("host", [sni])[0])
    path_hdr = unquote(query.get("path", ["/"])[0]) or "/"

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
            query = parse_qs(p.query)
            user: dict = {
                "id": p.username,
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
                "streamSettings": _build_stream_settings(query, p.hostname or ""),
            }

        if base.startswith("vmess://"):
            b64 = base[8:]
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            net = str(data.get("net", "tcp")).lower()
            stream: dict = {"network": net}
            if str(data.get("tls", "")).lower() == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {
                    "serverName": data.get("sni") or data.get("host", ""),
                    "allowInsecure": False,
                }
            if net == "ws":
                stream["wsSettings"] = {
                    "path": data.get("path", "/") or "/",
                    "headers": {"Host": data.get("host", "")},
                }
            elif net == "grpc":
                stream["grpcSettings"] = {"serviceName": data.get("path", "")}
            return {
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": data.get("add"),
                            "port": int(data.get("port", 443)),
                            "users": [
                                {
                                    "id": data.get("id"),
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
            query = parse_qs(p.query)
            if "security" not in query:
                query["security"] = ["tls"]
            return {
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": p.hostname,
                            "port": int(p.port or 443),
                            "password": p.username,
                        }
                    ]
                },
                "streamSettings": _build_stream_settings(query, p.hostname or ""),
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


def measure_speed_mbps(proxies: dict) -> float:
    speeds: list[float] = []
    try:
        with requests.get(
            SPEEDTEST_URL,
            proxies=proxies,
            timeout=5,
            stream=True,
        ) as r:
            if r.status_code != 200:
                return 0.0
            downloaded = 0
            start = time.perf_counter()
            for chunk in r.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                downloaded += len(chunk)
                elapsed = time.perf_counter() - start
                if elapsed > 0.1 and downloaded > 0:
                    speeds.append((downloaded / (1024 * 1024) * 8) / elapsed)
                if elapsed >= SPEEDTEST_TIMEOUT:
                    break
    except requests.RequestException:
        return 0.0
    return statistics.median(speeds) if speeds else 0.0


def evaluate_config(uri: str, meta: str) -> tuple[bool, float]:
    """Возвращает (is_ok, speed_mbps)."""
    hp = extract_host_port(uri)
    if not hp:
        return False, 0.0
    host, port = hp
    if host in ("0.0.0.0", "127.0.0.1", "localhost") or port <= 0:
        return False, 0.0

    ping = tcp_ping(host, port)
    if ping is None or ping > MAX_TCP_PING_MS:
        return False, 0.0

    outbound = uri_to_outbound(uri)
    if not outbound:
        return False, 0.0

    socks_port = get_free_port()
    proc, cfg_path = _spawn_xray(outbound, socks_port)
    if not proc:
        return False, 0.0

    try:
        if not wait_for_port(socks_port):
            return False, 0.0

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/128.0.0.0 Safari/537.36"
            )
        }

        success = 0
        for url in TEST_URLS:
            try:
                r = requests.get(
                    url,
                    proxies=proxies,
                    headers=headers,
                    timeout=TIMEOUT_PER_URL,
                )
                if r.status_code in (200, 204):
                    if r.status_code == 204 or len(r.content or b"") > 0:
                        success += 1
                        if success >= MIN_SUCCESS:
                            break
            except requests.RequestException:
                continue

        if success < MIN_SUCCESS:
            return False, 0.0

        speed = measure_speed_mbps(proxies)
        return True, speed
    finally:
        _stop_xray(proc, cfg_path)


def lookup_country(host: str) -> tuple[str, str]:
    try:
        ip = socket.gethostbyname(host)
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,countryCode,country",
            timeout=3,
        )
        if r.ok:
            data = r.json()
            if data.get("status") == "success":
                cc = (data.get("countryCode") or "").upper()
                if cc in COUNTRY_MAP:
                    return COUNTRY_MAP[cc]
                country_en = data.get("country") or cc or "Server"
                return ("🌐", country_en)
    except Exception:
        pass
    return ("🌐", "Сервер")


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

    log(f"Collected {len(candidates)} unique candidates.")
    return candidates


def format_server_name(uri: str, meta: str) -> str:
    frag = unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    combined = f"{frag} {meta}".strip()
    if is_whitelist_entry(combined):
        ops = detect_operators(combined)
        return f"🇪🇺 white list ({ops})"
    hp = extract_host_port(uri)
    host = hp[0] if hp else ""
    flag, country_name = lookup_country(host)
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
    # (base_uri, title, speed_mbps)
    working: list[tuple[str, str, float]] = []

    def worker(item: tuple[str, str]):
        uri, meta = item
        ok, speed = evaluate_config(uri, meta)
        return uri, meta, ok, speed

    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        futures = [pool.submit(worker, c) for c in candidates]
        for idx, fut in enumerate(as_completed(futures), start=1):
            if time.time() - start_ts > MAX_RUNTIME_SECONDS:
                log("Reached MAX_RUNTIME_SECONDS limit, stopping.")
                break
            uri, meta, ok, speed = fut.result()
            hp = extract_host_port(uri)
            target_str = f"{hp[0]}:{hp[1]}" if hp else uri[:40]
            if ok:
                title = format_server_name(uri, meta)
                working.append((clean_uri(uri), title, speed))
                log(f"[{idx}/{len(candidates)}] OK ({speed:.2f} Mbps) {target_str} -> {title}")
            else:
                log(f"[{idx}/{len(candidates)}] FAIL {target_str}")

    # Сортируем от самого быстрого к более медленному
    working.sort(key=lambda x: x[2], reverse=True)

    final_links: list[str] = []
    for idx, (base_uri, title, speed) in enumerate(working):
        final_title = f"{title} ⚡" if idx == 0 else title
        if idx == 0:
            log(f"Fastest server: {final_title} ({speed:.2f} Mbps)")
        final_links.append(f"{base_uri}#{quote(final_title)}")

    with open(SUB_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final_links) + ("\n" if final_links else ""))

    update_readme(len(final_links))
    log(f"Done. Active servers written to {SUB_FILE}: {len(final_links)}")


if __name__ == "__main__":
    main()
