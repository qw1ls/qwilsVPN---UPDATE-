import base64
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from urllib.parse import quote, unquote, urlparse, parse_qs

import requests

SOURCES_URL = (
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/"
    "refs/heads/main/sources.txt"
)
BRAND_TAG = "@qw1lsVPN"
SUB_FILE = "sub.txt"
README_FILE = "README.md"

BLOCKED_SITES = [
    "https://www.youtube.com/generate_204",
    "https://rutracker.org/forum/index.php",
    "https://www.instagram.com/",
    "https://x.com/",
    "https://discord.com/",
]
MIN_PASSED_SITES = 3
SITE_TIMEOUT = 3
MAX_SERVERS_TO_TEST = 50
MAX_RUNTIME_SECONDS = 180

COUNTRY_MAP = {
    "RU": ("🇷🇺", "Россия"),
    "DE": ("🇩🇪", "Германия"),
    "NL": ("🇳🇱", "Нидерланды"),
    "FI": ("🇫🇮", "Финляндия"),
    "SE": ("🇸🇪", "Швеция"),
    "FR": ("🇫🇷", "Франция"),
    "GB": ("🇬🇧", "Великобритания"),
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
    "wl",
)


def log(msg: str) -> None:
    print(msg, flush=True)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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


def parse_vless_uri(uri: str) -> dict | None:
    uri = uri.strip()
    if not uri.startswith("vless://"):
        return None
    fragment = ""
    if "#" in uri:
        uri_no_frag, fragment = uri.split("#", 1)
        fragment = unquote(fragment)
    else:
        uri_no_frag = uri

    parsed = urlparse(uri_no_frag)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port
    if not uuid or not host or not port:
        return None

    qs = parse_qs(parsed.query)
    first_qs = {k: v[0] for k, v in qs.items() if v}
    return {
        "raw": uri_no_frag,
        "uuid": uuid,
        "host": host,
        "port": int(port),
        "params": first_qs,
        "fragment": fragment,
    }


def build_xray_config(parsed: dict, socks_port: int) -> dict:
    p = parsed["params"]
    network = p.get("type", "tcp")
    security = p.get("security", "none")
    flow = p.get("flow", "")
    sni = p.get("sni", "")
    fp = p.get("fp", "chrome")
    pbk = p.get("pbk", "")
    sid = p.get("sid", "")
    spx = unquote(p.get("spx", ""))
    alpn_raw = p.get("alpn", "")
    alpn = [x.strip() for x in unquote(alpn_raw).split(",") if x.strip()] if alpn_raw else []
    path = unquote(p.get("path", "/"))
    host_hdr = unquote(p.get("host", sni or parsed["host"]))

    user_obj = {
        "id": parsed["uuid"],
        "encryption": p.get("encryption", "none"),
    }
    if flow:
        user_obj["flow"] = flow

    stream_settings = {
        "network": network,
        "security": security,
    }

    if security == "reality":
        stream_settings["realitySettings"] = {
            "show": False,
            "fingerprint": fp or "chrome",
            "serverName": sni,
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": spx,
        }
    elif security == "tls":
        tls_obj = {
            "serverName": sni or parsed["host"],
            "allowInsecure": p.get("allowInsecure", "0") in ("1", "true"),
            "fingerprint": fp or "chrome",
        }
        if alpn:
            tls_obj["alpn"] = alpn
        stream_settings["tlsSettings"] = tls_obj

    if network == "ws":
        stream_settings["wsSettings"] = {
            "path": path or "/",
            "headers": {"Host": host_hdr} if host_hdr else {},
        }
    elif network == "grpc":
        service_name = p.get("serviceName", "")
        stream_settings["grpcSettings"] = {
            "serviceName": service_name,
        }
    elif network in ("xhttp", "splithttp"):
        stream_settings["xhttpSettings"] = {
            "path": path or "/",
            "host": host_hdr,
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": parsed["host"],
                            "port": parsed["port"],
                            "users": [user_obj],
                        }
                    ]
                },
                "streamSettings": stream_settings,
            }
        ],
    }


def is_valid_site_response(resp: requests.Response) -> bool:
    if resp.status_code == 204:
        return True
    if resp.status_code == 200:
        return len(resp.content or b"") > 0
    return False


def check_vless_on_blocked_sites(parsed: dict) -> tuple[bool, float]:
    """Возвращает (is_ok, avg_latency_ms)."""
    port = get_free_port()
    cfg = build_xray_config(parsed, port)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(cfg, tf)
        cfg_path = tf.name

    proc = None
    try:
        proc = subprocess.Popen(
            ["xray", "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.25)

        proxies = {
            "http": f"socks5h://127.0.0.1:{port}",
            "https": f"socks5h://127.0.0.1:{port}",
        }
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/128.0.0.0 Safari/537.36"
            )
        }

        passed = 0
        latencies: list[float] = []

        for idx, url in enumerate(BLOCKED_SITES):
            if idx == 2 and passed == 0:
                break
            t0 = time.perf_counter()
            try:
                resp = requests.get(
                    url,
                    proxies=proxies,
                    headers=headers,
                    timeout=SITE_TIMEOUT,
                    allow_redirects=True,
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000.0
                if is_valid_site_response(resp):
                    passed += 1
                    latencies.append(elapsed_ms)
            except Exception:
                continue

        if passed >= MIN_PASSED_SITES and latencies:
            return True, sum(latencies) / len(latencies)
        return False, float("inf")
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.5)
            except subprocess.TimeoutExpired:
                proc.kill()
        if os.path.exists(cfg_path):
            os.remove(cfg_path)


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
                if cc == "RU":
                    return ("🇷🇺", "Россия")
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
    seen_raw: set[str] = set()
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
            try:
                sub_r = requests.get(uri_part, timeout=6)
                if sub_r.ok:
                    sub_txt = maybe_b64_decode(sub_r.text)
                    for sline in sub_txt.splitlines():
                        sline = sline.strip()
                        if sline.startswith("vless://"):
                            frag = unquote(sline.split("#", 1)[1]) if "#" in sline else ""
                            combined_meta = f"{line_meta} {frag}".strip()
                            base_uri = sline.split("#", 1)[0]
                            if base_uri not in seen_raw:
                                seen_raw.add(base_uri)
                                candidates.append((sline, combined_meta))
            except Exception:
                continue
        elif uri_part.startswith("vless://"):
            frag = unquote(uri_part.split("#", 1)[1]) if "#" in uri_part else ""
            combined_meta = f"{line_meta} {frag}".strip()
            base_uri = uri_part.split("#", 1)[0]
            if base_uri not in seen_raw:
                seen_raw.add(base_uri)
                candidates.append((uri_part, combined_meta))

    log(f"Collected {len(candidates)} unique vless candidates.")
    return candidates


def format_server_name(parsed: dict, meta: str) -> str:
    combined = f"{parsed['fragment']} {meta}".strip()
    if is_whitelist_entry(combined):
        ops = detect_operators(combined)
        return f"🇪🇺 white list ({ops})"
    flag, country_name = lookup_country(parsed["host"])
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
    candidates = collect_candidates_from_sources()[:MAX_SERVERS_TO_TEST]
    # Храним кортежи: (raw_uri, title, latency_ms)
    working_entries: list[tuple[str, str, float]] = []

    for i, (uri, meta) in enumerate(candidates, start=1):
        if time.time() - start_ts > MAX_RUNTIME_SECONDS:
            log("Reached MAX_RUNTIME_SECONDS limit, finishing check early.")
            break
        parsed = parse_vless_uri(uri)
        if not parsed:
            continue
        log(f"[{i}/{len(candidates)}] Checking {parsed['host']}:{parsed['port']}...")
        ok, avg_ms = check_vless_on_blocked_sites(parsed)
        if ok:
            title = format_server_name(parsed, meta)
            working_entries.append((parsed["raw"], title, avg_ms))
            log(f"  -> OK ({avg_ms:.0f} ms): {title}")
        else:
            log("  -> FAIL")

    fastest_idx = None
    if working_entries:
        fastest_idx = min(
            range(len(working_entries)),
            key=lambda idx: working_entries[idx][2],
        )

    final_links: list[str] = []
    for idx, (raw_uri, title, avg_ms) in enumerate(working_entries):
        final_title = f"{title} ⚡" if idx == fastest_idx else title
        if idx == fastest_idx:
            log(f"Fastest server: {final_title} ({avg_ms:.0f} ms)")
        final_links.append(f"{raw_uri}#{quote(final_title)}")

    with open(SUB_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(final_links) + ("\n" if final_links else ""))

    update_readme(len(final_links))
    log(f"Done. Active servers written to {SUB_FILE}: {len(final_links)}")


if __name__ == "__main__":
    main()
