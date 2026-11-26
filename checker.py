import base64
import concurrent.futures
import json
import os
import re
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
RU_CHECK_URL = os.getenv("RU_CHECK_URL", "https://www.gosuslugi.ru/").strip()
WORKING_OUTPUT = "working_configs.txt"
BLACKLIST_FILE = "blacklist_local.txt"
MAX_WORKERS = 16
TIMEOUT_SEC = 8

SCHEME_PATTERN = re.compile(r"(?:vless|vmess|trojan|ss)://[^\s\"'<>]+", re.IGNORECASE)


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
    resp = requests.get(sources_url, timeout=15)
    resp.raise_for_status()
    source_urls = [
        line.strip()
        for line in resp.text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    all_links = set()
    for url in source_urls:
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200 and r.text:
                for link in extract_links(r.text):
                    all_links.add(link)
        except requests.RequestException:
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


def check_via_ru_proxy(test_url: str) -> bool:
    if not RU_EGRESS_PROXY:
        return True
    proxies = {"http": RU_EGRESS_PROXY, "https": RU_EGRESS_PROXY}
    try:
        r = requests.get(test_url, proxies=proxies, timeout=TIMEOUT_SEC)
        return r.status_code < 500
    except requests.RequestException:
        return False


def test_single_link(uri: str) -> tuple[str, bool]:
    outbound = build_outbound(uri)
    if not outbound:
        return uri, False

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
            ["xray", "run", "-c", tmp_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.35)

        socks_url = f"socks5h://127.0.0.1:{local_port}"
        proxies = {"http": socks_url, "https": socks_url}

        # Проверка доступности целевого ресурса из РФ через проверяемый сервер
        resp = requests.get(RU_CHECK_URL, proxies=proxies, timeout=TIMEOUT_SEC)
        ok = resp.status_code < 500

        # Дополнительно проверяем доступность через внешний RU-шлюз, если задан
        if ok and RU_EGRESS_PROXY:
            ok = check_via_ru_proxy(RU_CHECK_URL)

        return uri, ok
    except Exception:
        return uri, False
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
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
    blacklist = load_blacklist(BLACKLIST_FILE)
    candidates = [u for u in fetch_sources(SOURCES_LIST_URL) if u not in blacklist]

    working: list[str] = []
    failed: list[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for uri, is_ok in executor.map(test_single_link, candidates):
            if is_ok:
                working.append(uri)
            else:
                failed.append(uri)

    with open(WORKING_OUTPUT, "w", encoding="utf-8") as f:
        for item in working:
            f.write(item + "\n")

    updated_blacklist = sorted(blacklist.union(failed))
    with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
        for item in updated_blacklist:
            f.write(item + "\n")

    print(f"Checked: {len(candidates)} | Working: {len(working)} | Failed: {len(failed)}")


if __name__ == "__main__":
    main()
