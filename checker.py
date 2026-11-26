import base64
import concurrent.futures
import datetime
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.parse
from typing import Optional

import requests

SOURCES_LIST_URL = os.getenv(
    "SOURCES_LIST_URL",
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/refs/heads/main/sources.txt",
)
RU_EGRESS_PROXY = os.getenv("RU_EGRESS_PROXY", "").strip()
RU_CHECK_URL = os.getenv("RU_CHECK_URL", "https://www.gstatic.com/generate_204").strip()
SPEED_TEST_URL = os.getenv(
    "SPEED_TEST_URL",
    "https://raw.githubusercontent.com/BitDoctor/speed-test-file/refs/heads/master/5mb.txt",
).strip()

# Порог скорости в Мбит/с: поставьте "0" или "0.1", чтобы не отсеивать медленные но рабочие ноды
MIN_SPEED_MBPS = float(os.getenv("MIN_SPEED_MBPS", "0.2"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))
MAX_CANDIDATES = int(os.getenv("MAX_CANDIDATES", "300"))
MAX_RUN_SECONDS = int(os.getenv("MAX_RUN_SECONDS", "360"))
TIMEOUT_SEC = float(os.getenv("TIMEOUT_SEC", "6"))

SUBSCRIPTION_TITLE = "antiRKN FREE"
WORKING_OUTPUT = "working_configs.txt"
SUBSCRIPTION_OUTPUT = "subscription.txt"
BLACKLIST_FILE = "blacklist_local.txt"

SCHEME_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+", re.IGNORECASE)


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def find_xray_binary() -> str:
    found = shutil.which("xray")
    if found:
        return found
    for candidate in ("/usr/local/bin/xray", os.path.abspath("xray_bin/xray")):
        if os.path.exists(candidate):
            return candidate
    return "xray"


XRAY_BIN = find_xray_binary()


def country_code_to_flag(code: str) -> str:
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(127397 + ord(ch)) for ch in code)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def decode_base64_smart(text: str) -> str:
    cleaned = re.sub(r"\s+", "", text)
    if not cleaned or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", cleaned):
        return ""
    padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
            decoded = raw.decode("utf-8", errors="ignore")
            if "://" in decoded:
                return decoded
        except Exception:
            continue
    return ""


def extract_links(content: str) -> list[str]:
    links = set()
    for match in SCHEME_PATTERN.findall(content):
        links.add(match.strip())

    decoded = decode_base64_smart(content)
    if decoded:
        for match in SCHEME_PATTERN.findall(decoded):
            links.add(match.strip())

    return list(links)


def fetch_sources(sources_url: str) -> list[str]:
    log(f"Downloading sources list: {sources_url}")
    resp = requests.get(sources_url, timeout=12)
    resp.raise_for_status()
    source_urls = [
        line.strip()
        for line in resp.text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    log(f"Found {len(source_urls)} subscription URLs")

    all_links = set()
    for idx, url in enumerate(source_urls, start=1):
        try:
            r = requests.get(url, timeout=8)
            if r.status_code == 200 and r.text:
                found = extract_links(r.text)
                all_links.update(found)
                log(
                    f"Source [{idx}/{len(source_urls)}] OK: +{len(found)} links "
                    f"(total unique: {len(all_links)})"
                )
            else:
                log(f"Source [{idx}/{len(source_urls)}] HTTP {r.status_code}")
        except requests.RequestException as e:
            log(f"Source [{idx}/{len(source_urls)}] error: {type(e).__name__}")
            continue

    return sorted(all_links)


def parse_vless_outbound(uri: str) -> Optional[dict]:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme.lower() != "vless" or not parsed.hostname or not parsed.port:
        return None

    qs = urllib.parse.parse_qs(parsed.query)
    security = qs.get("security", ["none"])[0]
    network = qs.get("type", ["tcp"])[0]
    flow = qs.get("flow", [""])[0]

    user = {"id": urllib.parse.unquote(parsed.username or ""), "encryption": "none"}
    if flow:
        user["flow"] = flow

    stream_settings: dict = {"network": network, "security": security}

    if network == "ws":
        stream_settings["wsSettings"] = {
            "path": qs.get("path", ["/"])[0],
            "headers": {"Host": qs.get("host", [parsed.hostname])[0]},
        }
    elif network == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": qs.get("serviceName", [""])[0],
        }

    if security == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": qs.get("sni", [parsed.hostname])[0],
            "allowInsecure": qs.get("allowInsecure", ["0"])[0] in ("1", "true"),
        }
    elif security == "reality":
        stream_settings["realitySettings"] = {
            "show": False,
            "serverName": qs.get("sni", [parsed.hostname])[0],
            "fingerprint": qs.get("fp", ["chrome"])[0],
            "publicKey": qs.get("pbk", [""])[0],
            "shortId": qs.get("sid", [""])[0],
            "spiderX": qs.get("spx", ["/"])[0],
        }

    return {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": parsed.hostname,
                    "port": int(parsed.port),
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream_settings,
    }


def parse_vmess_outbound(uri: str) -> Optional[dict]:
    b64_part = uri[8:].split("#", 1)[0]
    decoded = decode_base64_smart(b64_part)
    if not decoded:
        return None
    try:
        cfg = json.loads(decoded)
    except json.JSONDecodeError:
        return None

    host = cfg.get("add")
    port = cfg.get("port")
    uid = cfg.get("id")
    if not host or not port or not uid:
        return None

    net = cfg.get("net", "tcp")
    tls = cfg.get("tls", "")
    stream_settings: dict = {"network": net, "security": "tls" if tls == "tls" else "none"}
    if net == "ws":
        stream_settings["wsSettings"] = {
            "path": cfg.get("path", "/"),
            "headers": {"Host": cfg.get("host") or host},
        }
    if stream_settings["security"] == "tls":
        stream_settings["tlsSettings"] = {
            "serverName": cfg.get("sni") or cfg.get("host") or host,
            "allowInsecure": True,
        }

    return {
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": host,
                    "port": int(port),
                    "users": [{"id": uid, "alterId": int(cfg.get("aid", 0)), "security": "auto"}],
                }
            ]
        },
        "streamSettings": stream_settings,
    }


def parse_trojan_outbound(uri: str) -> Optional[dict]:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme.lower() != "trojan" or not parsed.hostname or not parsed.port:
        return None
    qs = urllib.parse.parse_qs(parsed.query)
    sni = qs.get("sni", [parsed.hostname])[0]
    return {
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": parsed.hostname,
                    "port": int(parsed.port),
                    "password": urllib.parse.unquote(parsed.username or ""),
                }
            ]
        },
        "streamSettings": {
            "network": qs.get("type", ["tcp"])[0],
            "security": "tls",
            "tlsSettings": {
                "serverName": sni,
                "allowInsecure": qs.get("allowInsecure", ["0"])[0] in ("1", "true"),
            },
        },
    }


def build_outbound(uri: str) -> Optional[dict]:
    lower = uri.lower()
    if lower.startswith("vless://"):
        return parse_vless_outbound(uri)
    if lower.startswith("vmess://"):
        return parse_vmess_outbound(uri)
    if lower.startswith("trojan://"):
        return parse_trojan_outbound(uri)
    return None


def detect_geo_via_proxies(proxies: dict[str, str]) -> tuple[str, str]:
    try:
        r = requests.get(
            "http://ip-api.com/json/?fields=status,country,countryCode",
            proxies=proxies,
            timeout=5,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                code = data.get("countryCode", "")
                name = data.get("country", "Unknown")
                return country_code_to_flag(code), name
    except Exception:
        pass
    return "🌐", "Unknown"


def check_ru_reachability(proxies: dict[str, str]) -> bool:
    if RU_EGRESS_PROXY:
        ru_proxies = {"http": RU_EGRESS_PROXY, "https": RU_EGRESS_PROXY}
        try:
            r = requests.get(RU_CHECK_URL, proxies=ru_proxies, timeout=TIMEOUT_SEC)
            if r.status_code >= 500:
                return False
        except requests.RequestException:
            return False

    try:
        r = requests.get(RU_CHECK_URL, proxies=proxies, timeout=TIMEOUT_SEC)
        return r.status_code < 500
    except requests.RequestException:
        return False


def measure_speed_mbps(proxies: dict[str, str]) -> float:
    start = time.monotonic()
    total_bytes = 0
    with requests.get(SPEED_TEST_URL, proxies=proxies, stream=True, timeout=TIMEOUT_SEC) as resp:
        resp.raise_for_status()
        for chunk in resp.iter_content(chunk_size=32768):
            if not chunk:
                break
            total_bytes += len(chunk)
            if time.monotonic() - start >= 2.5:
                break

    elapsed = max(time.monotonic() - start, 0.001)
    mbps = (total_bytes * 8) / (elapsed * 1_000_000)
    return round(mbps, 1)


def format_server_label(flag: str, country_name: str, speed_mbps: float, updated_at: str) -> str:
    return (
        f"{flag} {country_name} | последнее обновление {updated_at} | "
        f"{speed_mbps:.1f} Mbps | @qw1lsVPN"
    )


def rename_config(uri: str, label: str) -> str:
    if uri.lower().startswith("vmess://"):
        b64_part = uri[8:].split("#", 1)[0]
        decoded = decode_base64_smart(b64_part)
        if decoded:
            try:
                cfg = json.loads(decoded)
                cfg["ps"] = label
                new_b64 = base64.b64encode(
                    json.dumps(cfg, ensure_ascii=False).encode("utf-8")
                ).decode("utf-8")
                return f"vmess://{new_b64}"
            except Exception:
                pass

    base_uri = re.split(r"[#\s]", uri.strip(), maxsplit=1)[0]
    encoded_label = urllib.parse.quote(label)
    return f"{base_uri}#{encoded_label}"


def test_single_link(uri: str, updated_at: str) -> tuple[str, float, Optional[str]]:
    outbound = build_outbound(uri)
    if not outbound:
        return uri, 0.0, None

    local_port = find_free_port()
    xray_config = {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "socks",
                "settings": {"udp": False},
            }
        ],
        "outbounds": [outbound],
    }

    proc = None
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(xray_config, tf)
            tmp_path = tf.name

        proc = subprocess.Popen(
            [XRAY_BIN, "run", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.25)

        socks_url = f"socks5h://127.0.0.1:{local_port}"
        proxies = {"http": socks_url, "https": socks_url}

        if not check_ru_reachability(proxies):
            return uri, 0.0, None

        speed_mbps = measure_speed_mbps(proxies)
        if speed_mbps < MIN_SPEED_MBPS:
            return uri, speed_mbps, None

        flag, country_name = detect_geo_via_proxies(proxies)
        label = format_server_label(flag, country_name, speed_mbps, updated_at)
        renamed_uri = rename_config(uri, label)
        return uri, speed_mbps, renamed_uri
    except Exception:
        return uri, 0.0, None
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def load_blacklist(path: str) -> set[str]:
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def main() -> None:
    started_at = time.monotonic()
    updated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%d.%m %H:%M UTC")
    blacklist = load_blacklist(BLACKLIST_FILE)
    log(f"Loaded blacklist entries: {len(blacklist)}")

    all_links = fetch_sources(SOURCES_LIST_URL)
    candidates = [u for u in all_links if u not in blacklist]

    # Если почти все ссылки оказались в блэклисте — берём свежие ссылки из списка, чтобы не остаться с 0 кандидатов
    if not candidates and all_links:
        log("Blacklist filtered out all links, retrying fresh links from sources...")
        candidates = all_links

    candidates = candidates[:MAX_CANDIDATES]
    log(f"Candidates to test: {len(candidates)} (min_speed={MIN_SPEED_MBPS} Mbps)")

    results: list[tuple[float, str]] = []
    failed: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_uri = {
            executor.submit(test_single_link, uri, updated_at): uri for uri in candidates
        }
        done_count = 0
        for fut in concurrent.futures.as_completed(future_to_uri):
            done_count += 1
            fallback_uri = future_to_uri[fut]
            try:
                raw_uri, speed_mbps, renamed_uri = fut.result(timeout=TIMEOUT_SEC * 2 + 4)
            except Exception:
                raw_uri, speed_mbps, renamed_uri = fallback_uri, 0.0, None

            if renamed_uri:
                results.append((speed_mbps, renamed_uri))
            else:
                failed.append(raw_uri)

            if done_count % 25 == 0 or done_count == len(candidates):
                log(f"Progress: {done_count}/{len(candidates)} | Working so far: {len(results)}")

            if time.monotonic() - started_at > MAX_RUN_SECONDS:
                log(f"Reached time limit ({MAX_RUN_SECONDS}s), stopping early cleanly")
                break

    # Сортируем по убыванию скорости: самая высокая скорость сверху
    results.sort(key=lambda item: item[0], reverse=True)
    sorted_configs = [item[1] for item in results]

    if sorted_configs:
        with open(WORKING_OUTPUT, "w", encoding="utf-8") as f:
            f.write(f"# profile-title: {SUBSCRIPTION_TITLE}\n")
            for cfg in sorted_configs:
                f.write(cfg + "\n")

        raw_sub_text = "\n".join([f"# profile-title: {SUBSCRIPTION_TITLE}"] + sorted_configs)
        b64_sub = base64.b64encode(raw_sub_text.encode("utf-8")).decode("utf-8")
        with open(SUBSCRIPTION_OUTPUT, "w", encoding="utf-8") as f:
            f.write(b64_sub + "\n")
    else:
        log("No configs passed speed/check threshold; keeping existing subscription files untouched")

    updated_blacklist = sorted(blacklist.union(failed))
    with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
        for item in updated_blacklist:
            f.write(item + "\n")

    top_speed = results[0][0] if results else 0.0
    log(
        f"Done in {time.monotonic() - started_at:.1f}s | Subscription: {SUBSCRIPTION_TITLE} | "
        f"Working: {len(sorted_configs)} | Top speed: {top_speed:.1f} Mbps | Failed: {len(failed)}"
    )


if __name__ == "__main__":
    main()
