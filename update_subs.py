#!/usr/bin/env python3
import os
import sys
import time
import json
import base64
import socket
import subprocess
import tempfile
import signal
import threading
import re
import random
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ipaddress

TIMEOUT_PER_URL = 6
MAX_TCP_PING_MS = 600
TCP_PING_TIMEOUT = MAX_TCP_PING_MS / 1000

SOURCES_LIST_URL = "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/refs/heads/main/sources.txt"
WHITELIST_SOURCES = [
    "https://raw.githubusercontent.com/LimeHi/LimeVPN/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt"
]

OUTPUT_FILE = "sub.txt"
README_FILE = "README.md"
IP_BLACKLIST_FILE = "ip_blacklist.txt"

TEST_URLS = [
    "https://www.instagram.com",
    "https://discord.com",
    "https://x.com",
    "https://en.wikipedia.org",
    "https://www.bbc.com",
    "https://medium.com"
]

blacklist_dict = {}
blacklist_lock = Lock()
country_cache = {}
dns_cache = {}
STATIC_IP_BLACKLIST = []

_session = requests.Session()
_session.headers.update({
    "User-Agent": "Happ/4.1.0/Android/17860741775021899510",
    "X-Device-Locale": "ru",
    "X-Hwid": "9dcd98947a040627",
    "X-Device-Os": "Android",
    "X-Ver-Os": "16",
    "X-Device-Model": "Samsung",
    "Connection": "close",
})
_retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500])
_adapter = HTTPAdapter(max_retries=_retry_strategy, pool_connections=15, pool_maxsize=15)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)

def resolve_host(host):
    if not host: return None
    try:
        socket.inet_aton(host)
        return host
    except OSError: pass
    if host in dns_cache: return dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
        dns_cache[host] = ip
        return ip
    except socket.gaierror:
        dns_cache[host] = None
        return None

def get_country(host):
    ip = resolve_host(host) or host
    if not ip: return "Другие", "🌍"
    if ip in country_cache: return country_cache[ip]
    
    providers = [
        (f"http://ip-api.com/json/{ip}?fields=status,country,countryCode", lambda d: (d.get("country", ""), d.get("countryCode", "").upper()) if d.get("status") == "success" else None),
        (f"https://ipwho.is/{ip}", lambda d: (d.get("country", ""), d.get("country_code", "").upper()) if d.get("country_code") else None),
        (f"https://freeipapi.com/api/json/{ip}", lambda d: (d.get("countryName", ""), d.get("countryCode", "").upper()) if d.get("countryCode") else None)
    ]
    
    random.shuffle(providers)
    for url, parse in providers:
        try:
            r = _session.get(url, timeout=3)
            if r.status_code == 200:
                res = parse(r.json())
                if res and res[1]:
                    code = res[1]
                    flag = chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
                    val = (res[0], flag)
                    country_cache[ip] = val
                    return val
        except Exception:
            continue
            
    res = ("Другие", "🌍")
    country_cache[ip] = res
    return res

def prefetch_countries_batch(hosts):
    print(f"🌍 Определение локаций ({len(hosts)} серверов)...")
    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(get_country, hosts))
    print("✅ Локации успешно определены.")

def load_black_list():
    global STATIC_IP_BLACKLIST
    if os.path.exists(IP_BLACKLIST_FILE):
        with open(IP_BLACKLIST_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try: STATIC_IP_BLACKLIST.append(ipaddress.ip_network(line, strict=False))
                    except ValueError: pass

def is_ip_blacklisted(host):
    if not STATIC_IP_BLACKLIST or not host: return False
    try: ip = ipaddress.ip_address(host)
    except ValueError:
        resolved = resolve_host(host)
        if not resolved: return False
        try: ip = ipaddress.ip_address(resolved)
        except ValueError: return False
    for net in STATIC_IP_BLACKLIST:
        if ip in net: return True
    return False

def tcp_ping(host, port):
    try:
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TCP_PING_TIMEOUT)
            sock.connect((host, port))
            return (time.perf_counter() - start) * 1000
    except OSError: return None

def get_free_port():
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def wait_for_port(port, timeout=2.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.connect(("127.0.0.1", port))
                return True
        except OSError: time.sleep(0.1)
    return False

def extract_host_port(line):
    line = line.split("#")[0].strip()
    if len(line) > 8192: return None
    try:
        p = urlparse(line)
        if p.scheme in ("vless", "trojan"):
            if not p.hostname: return None
            return p.hostname, p.port or 443
        if p.scheme == "vmess":
            b64 = line[8:]
            if not b64: return None
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
            add = data.get("add")
            if not add: return None
            return add, int(data.get("port", 443))
    except Exception: pass
    return None

def clean_config_line(line):
    return line.split("#")[0].strip()

def _build_stream_settings(query: dict, fallback_host: str) -> dict:
    network = query.get("type", ["tcp"])[0] or "tcp"
    security = query.get("security", ["none"])[0] or "none"
    sni = query.get("sni", query.get("host", [fallback_host]))[0]
    fp = query.get("fp", [""])[0]
    stream = {"network": network}
    
    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "fingerprint": fp or "chrome", "serverName": sni,
            "publicKey": query.get("pbk", [""])[0], "shortId": query.get("sid", [""])[0],
            "spiderX": query.get("spx", [""])[0],
        }
    elif security == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp or "chrome", "allowInsecure": False}
        
    if network == "ws":
        stream["wsSettings"] = {"path": query.get("path", ["/"])[0], "headers": {"Host": query.get("host", [sni])[0]}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": query.get("serviceName", [""])[0], "multiMode": query.get("mode", [""])[0] == "multi"}
    return stream

def parse_vless_to_outbound(line, tag):
    p = urlparse(line)
    query = parse_qs(p.query)
    user = {"id": p.username, "encryption": "none"}
    if flow := query.get("flow", [""])[0]: user["flow"] = flow
    return {
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": p.hostname, "port": p.port or 443, "users": [user]}]},
        "streamSettings": _build_stream_settings(query, p.hostname),
    }

def parse_vmess_to_outbound(line, tag):
    b64 = line[8:].split("#")[0]
    b64 += "=" * (-len(b64) % 4)
    data = json.loads(base64.b64decode(b64).decode("utf-8", errors='ignore'))
    net = data.get("net", "tcp")
    stream = {"network": net}
    if data.get("tls") == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": data.get("sni") or data.get("host", ""), "allowInsecure": False}
    if net == "ws":
        stream["wsSettings"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", "")}}
    return {
        "tag": tag, "protocol": "vmess",
        "settings": {"vnext": [{"address": data.get("add"), "port": int(data.get("port", 443)), "users": [{"id": data.get("id"), "alterId": int(data.get("aid", 0) or 0), "security": "auto"}]}]},
        "streamSettings": stream,
    }

def parse_trojan_to_outbound(line, tag):
    p = urlparse(line)
    query = parse_qs(p.query)
    if "security" not in query: query["security"] = ["tls"]
    return {
        "tag": tag, "protocol": "trojan",
        "settings": {"servers": [{"address": p.hostname, "port": p.port or 443, "password": p.username}]},
        "streamSettings": _build_stream_settings(query, p.hostname),
    }

def _line_to_outbound(line, tag="test"):
    cleaned = clean_config_line(line)
    try:
        if cleaned.startswith("vless://"): return parse_vless_to_outbound(cleaned, tag)
        if cleaned.startswith("vmess://"): return parse_vmess_to_outbound(cleaned, tag)
        if cleaned.startswith("trojan://"): return parse_trojan_to_outbound(cleaned, tag)
    except Exception: pass
    return None

def _spawn_xray(outbound, socks_port):
    config = {
        "inbounds": [{"port": socks_port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [outbound],
        "log": {"loglevel": "none"},
    }
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            path = f.name
        proc = subprocess.Popen(
            ["xray", "-config", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        return proc, path
    except OSError: return None, None

def _stop_xray(proc, path):
    if proc:
        try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError: pass
        try: proc.wait(timeout=1)
        except subprocess.TimeoutExpired: pass
    if path and os.path.exists(path):
        try: os.unlink(path)
        except OSError: pass

def test_single_config(line):
    original = line.strip()
    hp = extract_host_port(original)
    if not hp: return None
    host, port = hp
    if host in ("0.0.0.0", "127.0.0.1", "localhost") or port == 0: return None
    if is_ip_blacklisted(host): return None
    
    ping = tcp_ping(host, port)
    if ping is None or ping > 600:
        return None
        
    outbound = _line_to_outbound(original)
    if not outbound: return None
    socks_port = get_free_port()
    proc, cfg = _spawn_xray(outbound, socks_port)
    if not proc: return None
    
    try:
        if not wait_for_port(socks_port):
            return None
            
        proxies = {"http": f"socks5://127.0.0.1:{socks_port}", "https": f"socks5://127.0.0.1:{socks_port}"}
        success_count = 0
        
        for url in TEST_URLS:
            try:
                r = _session.get(url, proxies=proxies, timeout=TIMEOUT_PER_URL)
                if r.status_code == 200:
                    success_count += 1
                    if success_count >= 2:
                        return original, host, ping
            except Exception:
                continue
        return None
    except Exception:
        return None
    finally:
        _stop_xray(proc, cfg)

def update_readme(total_nodes):
    msk_time = datetime.now(timezone(timedelta(hours=3))).strftime("%d.%m.%Y в %H:%M МСК")
    readme_content = (
        "# @qw1lsVPN FREE\n\n"
        "⚡ **Автоматическая подписка на рабочие VLESS/VMess/Trojan ноды**\n"
        "Обновляется регулярно через GitHub Actions. Без рекламы и ограничений.\n\n"
        "---\n\n"
        "### 📊 Статус:\n"
        f"* **Активных серверов:** `{total_nodes}`\n"
        f"* **Последнее обновление:** `{msk_time}`\n\n"
        "---\n\n"
        "### 🔗 Ссылка на подписку:\n"
        "Добавьте эту ссылку в свой клиент (**Hiddify**, **NekoBox**, **v2rayNG**):\n\n"
        "```text\n"
        "[https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/refs/heads/main/sub.txt](https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/refs/heads/main/sub.txt)\n"
        "```\n"
    )
    with open(README_FILE, "w", encoding="utf-8") as f:
        f.write(readme_content)

def fetch_configs_from_url(url):
    configs = set()
    try:
        resp = _session.get(url, timeout=10)
        if resp.status_code == 200:
            content = resp.text
            try:
                decoded = base64.b64decode(content + "===").decode('utf-8', errors='ignore')
                if "://" in decoded: content = decoded
            except Exception: pass
            found = re.findall(r'((?:vless|vmess|trojan|ss)://[^\s<"]+)', content)
            for cfg in found: configs.add(cfg)
    except Exception as e:
        print(f"⚠️ Ошибка загрузки {url}: {e}")
    return configs

def main():
    load_black_list()
    
    print("📥 Загрузка основных источников из sources.txt...")
    main_raw_configs = set()
    try:
        r = _session.get(SOURCES_LIST_URL, timeout=10)
        if r.status_code == 200:
            urls = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")]
            for url in urls:
                main_raw_configs.update(fetch_configs_from_url(url))
    except Exception as e:
        print(f"⚠️ Ошибка загрузки списка источников: {e}")

    print("📥 Загрузка специальных белых списков (White List)...")
    whitelist_raw_configs = set()
    for wl_url in WHITELIST_SOURCES:
        whitelist_raw_configs.update(fetch_configs_from_url(wl_url))

    all_configs = main_raw_configs.union(whitelist_raw_configs)
    print(f"🔎 Найдено уникальных конфигов: {len(all_configs)}. Запуск жесткой проверки по заблокированным сайтам...")
    
    valid_nodes = []
    whitelist_valid = set()
    
    hosts_to_check = [extract_host_port(c)[0] for c in all_configs if extract_host_port(c)]
    prefetch_countries_batch(hosts_to_check)
    
    with ThreadPoolExecutor(max_workers=40) as executor:
        futures = {executor.submit(test_single_config, cfg): cfg for cfg in all_configs}
        for future in as_completed(futures):
            res = future.result()
            if res:
                cfg, host, ping = res
                country, flag = get_country(host)
                valid_nodes.append((country, flag, cfg, ping))
                if cfg in whitelist_raw_configs:
                    whitelist_valid.add(cfg)
                
    print(f"✅ Прошли строгую проверку: {len(valid_nodes)} серверов.")
    
    if not valid_nodes:
        print("❌ Нет рабочих серверов!")
        return

    non_wl_nodes = [n for n in valid_nodes if n[2] not in whitelist_valid]
    best_node = min(non_wl_nodes if non_wl_nodes else valid_nodes, key=lambda x: x[3])
    
    final_configs = []
    time_str = datetime.now(timezone(timedelta(hours=3))).strftime("%d.%m %H:%M")
    total_count = len(valid_nodes)
    
    # 1. Самый первый сервер — лидер с пингом
    b_country, b_flag, b_cfg, b_ping = best_node
    b_base_url = b_cfg.split('#')[0]
    best_name = f"{b_flag} ⚡ {b_country} ({int(b_ping)}ms)"
    best_full_name = unquote(f"{best_name} | {total_count} серверов | Обновлено: {time_str} | @qw1lsVPN")
    final_configs.append(f"{b_base_url}#{urlparse(f'/?{best_full_name}').path or best_full_name}")
    
    # 2. Ноды из белых списков с флагом ЕС и описанием
    for country, flag, cfg, ping in valid_nodes:
        if cfg in whitelist_valid and cfg != b_cfg:
            base_url = cfg.split('#')[0]
            node_name = f"🇪🇺 White List"
            full_name = unquote(f"{node_name} | white list при крайних случаях! | {total_count} серверов | Обновлено: {time_str} | @qw1lsVPN")
            final_configs.append(f"{base_url}#{urlparse(f'/?{full_name}').path or full_name}")

    # 3. Остальные обычные сервера по странам
    country_groups = {}
    for country, flag, cfg, ping in valid_nodes:
        if cfg not in whitelist_valid and cfg != b_cfg:
            key = (country, flag)
            if key not in country_groups: country_groups[key] = []
            country_groups[key].append((cfg, ping))
        
    for (country, flag), nodes in country_groups.items():
        for cfg, ping in nodes:
            base_url = cfg.split('#')[0]
            node_name = f"{flag} {country}"
            full_name = unquote(f"{node_name} | {total_count} серверов | Обновлено: {time_str} | @qw1lsVPN")
            final_configs.append(f"{base_url}#{urlparse(f'/?{full_name}').path or full_name}")
            
    encoded_sub = base64.b64encode("\n".join(final_configs).encode('utf-8')).decode('utf-8')
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(encoded_sub)
        
    update_readme(len(final_configs))
    print(f"🎉 Готово! Файл подписки сохранен в {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
        
        
