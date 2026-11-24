#!/usr/bin/env python3
"""
VPN config checker для GitHub Actions.
Собирает конфиги из sources.txt, проверяет через xray, меряет скорость,
называет серверы "<флаг> <страна> @qw1lsVPN" и публикует working_configs.txt.
"""
import os
import sys
import re
import json
import time
import base64
import random
import signal
import socket
import ipaddress
import subprocess
import tempfile
from datetime import datetime
from threading import Lock
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ----------------------------------------------------------------------------
# Настройки
# ----------------------------------------------------------------------------
BRAND = "@qw1lsVPN"
PANEL_TITLE = BRAND
TG_LINK = "https://t.me/qw1lsVPN"

SOURCES_LIST_URL = os.environ.get(
    "SOURCES_LIST_URL",
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/refs/heads/main/sources.txt",
)
FETCH_PROXY = os.environ.get("FETCH_PROXY", "")

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
_repo = os.environ.get("GITHUB_REPOSITORY", "qw1ls/qwilsVPN---UPDATE-").split("/", 1)
REPO_OWNER, REPO_NAME = _repo[0], _repo[1]
BRANCH = os.environ.get("BRANCH", "main")
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "working_configs.txt")

TCP_PING_MS = int(os.environ.get("MAX_TCP_PING_MS", 1000))
TEST_TIMEOUT = int(os.environ.get("TIMEOUT_PER_URL", 8))
SPEEDTEST_TIMEOUT = int(os.environ.get("SPEEDTEST_TIMEOUT", 10))
MIN_SPEED = float(os.environ.get("MIN_SPEED", 5.0))          # Мбит/с
MIN_SUCCESS = int(os.environ.get("MIN_SUCCESS", 2))
MAX_TO_TEST = int(os.environ.get("MAX_TO_TEST", 400))         # сколько отдать в xray-тест
MAX_FINAL = int(os.environ.get("MAX_FINAL", 150))             # сколько оставить в итоге

PING_WORKERS = int(os.environ.get("PING_WORKERS", 50))
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", 8))
FETCH_WORKERS = int(os.environ.get("FETCH_WORKERS", 6))
SPEEDTEST_WORKERS = int(os.environ.get("SPEEDTEST_WORKERS", 3))
XRAY_STARTUP_TIMEOUT = 3.0

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://telegram.org",
    "https://www.instagram.com",
    "https://www.cloudflare.com/cdn-cgi/trace",
]
SPEEDTEST_URLS = [
    "https://speed.cloudflare.com/__down?bytes=10000000",
    "https://raw.githubusercontent.com/BitDoctor/speed-test-file/refs/heads/master/5mb.txt",
]

BLOCKED_COUNTRIES = {"CN", "IR", "AF", "TM", "KP"}   # серверы из этих стран не публикуем
BLACKLIST_AGE_LIMIT = 5 * 3600
BLACKLIST_FILE = "blacklist_local.txt"

# необязательные файлы (если их нет, просто пропускаются)
IP_BLACKLIST_FILE = os.environ.get("IP_BLACKLIST_FILE", "ip_blacklist.txt")
DOMAIN_BLACKLIST_FILE = os.environ.get("DOMAIN_BLACKLIST_FILE", "blacklist_domains.txt")
WS_PATH_BLOCKLIST_FILE = os.environ.get("WS_PATCH_BLOCKLIST_FILE", "ws_patch_blocklist.txt")

TOTAL_BYTES = 67 * 1024 ** 4
EXPIRE_TIMESTAMP = 4102444800  # 2100-01-01

# ----------------------------------------------------------------------------
# Глобальное состояние
# ----------------------------------------------------------------------------
blacklist_dict = {}
blacklist_lock = Lock()
country_cache = {}
dns_cache = {}
STATIC_IP_BLACKLIST = []
BLACK_DOMAINS = set()
WS_PATH_BLOCKLIST = set()
_black_regex = None

_session = requests.Session()
_session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; qw1lsVPN-checker/1.0)"})
_retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=20, pool_maxsize=20)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)


# ----------------------------------------------------------------------------
# Утилиты
# ----------------------------------------------------------------------------
def resolve_host(host):
    if not host:
        return None
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    if host in dns_cache:
        return dns_cache[host]
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        ip = None
    dns_cache[host] = ip
    return ip


def country_code_to_flag(code):
    if not code or len(code) != 2:
        return "🌐"
    c = code.upper()
    return chr(ord(c[0]) + 0x1F1A5) + chr(ord(c[1]) + 0x1F1A5)


def get_free_port():
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def wait_for_port(port, timeout=XRAY_STARTUP_TIMEOUT):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                s.connect(("127.0.0.1", port))
                return True
        except OSError:
            time.sleep(0.1)
    return False


def tcp_ping(host, port):
    ip = resolve_host(host)
    if not ip:
        return None
    try:
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TCP_PING_MS / 1000)
            sock.connect((ip, port))
        return (time.perf_counter() - start) * 1000
    except OSError:
        return None


# ----------------------------------------------------------------------------
# Страна по IP
# ----------------------------------------------------------------------------
def _p_ipapi(d):
    if d.get("status") == "success":
        return d.get("country", ""), d.get("countryCode", "").upper()


def _p_ipwho(d):
    if d.get("country_code"):
        return d.get("country", ""), d.get("country_code", "").upper()


def _p_freeipapi(d):
    if d.get("countryCode"):
        return d.get("countryName", ""), d.get("countryCode", "").upper()


def _p_countryis(d):
    if d.get("country"):
        return d.get("country", ""), d.get("country", "").upper()


def _p_dbip(d):
    if d.get("countryCode"):
        return d.get("countryName", ""), d.get("countryCode", "").upper()


def get_country(host):
    ip = resolve_host(host) or host
    if not ip:
        return "", ""
    if ip in country_cache:
        return country_cache[ip]

    providers = [
        (f"http://ip-api.com/json/{ip}?fields=status,country,countryCode", _p_ipapi),
        (f"https://ipwho.is/{ip}", _p_ipwho),
        (f"https://freeipapi.com/api/json/{ip}", _p_freeipapi),
        (f"https://api.country.is/{ip}", _p_countryis),
        (f"http://api.db-ip.com/v2/free/{ip}", _p_dbip),
    ]
    random.shuffle(providers)
    for url, parse in providers:
        try:
            r = requests.get(url, timeout=4)
            if r.status_code == 200:
                res = parse(r.json())
                if res and res[1]:
                    # api.country.is отдаёт только код, имя подставим из других источников
                    country_cache[ip] = res
                    return res
        except (requests.RequestException, ValueError):
            continue
    country_cache[ip] = ("", "")
    return country_cache[ip]


def prefetch_countries(hosts):
    hosts = list(set(hosts))
    print(f"🌍 Определение стран ({len(hosts)} хостов)...")
    with ThreadPoolExecutor(max_workers=15) as ex:
        list(ex.map(get_country, hosts))
    print("✅ Страны определены.")


# ----------------------------------------------------------------------------
# Загрузка необязательных списков
# ----------------------------------------------------------------------------
def _read_lines(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def load_lists():
    global _black_regex
    STATIC_IP_BLACKLIST.clear()
    BLACK_DOMAINS.clear()
    WS_PATH_BLOCKLIST.clear()
    _black_regex = None

    for line in _read_lines(IP_BLACKLIST_FILE):
        try:
            STATIC_IP_BLACKLIST.append(ipaddress.ip_network(line, strict=False))
        except ValueError:
            pass
    for line in _read_lines(DOMAIN_BLACKLIST_FILE):
        BLACK_DOMAINS.add(line.lower())
    for line in _read_lines(WS_PATH_BLOCKLIST_FILE):
        WS_PATH_BLOCKLIST.add(line)
    print(f"Списки: IP-blacklist={len(STATIC_IP_BLACKLIST)}, "
          f"domain-blacklist={len(BLACK_DOMAINS)}, ws-paths={len(WS_PATH_BLOCKLIST)}")


def is_ip_blacklisted(host):
    if not STATIC_IP_BLACKLIST or not host:
        return False
    ip_s = host if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else resolve_host(host)
    if not ip_s:
        return False
    try:
        ip = ipaddress.ip_address(ip_s)
    except ValueError:
        return False
    return any(ip in net for net in STATIC_IP_BLACKLIST)


def is_domain_blacklisted(line):
    global _black_regex
    if not BLACK_DOMAINS:
        return False
    if _black_regex is None:
        doms = sorted(BLACK_DOMAINS, key=len, reverse=True)
        pat = r"(?<![a-zA-Z0-9-])(?:" + "|".join(map(re.escape, doms)) + r")(?![a-zA-Z0-9-])"
        _black_regex = re.compile(pat, re.IGNORECASE)
    return bool(_black_regex.search(line))


# ----------------------------------------------------------------------------
# Разбор конфигов
# ----------------------------------------------------------------------------
def clean_config_line(line):
    return line.split("#")[0].strip()


def _b64_json(b64):
    b64 += "=" * (-len(b64) % 4)
    return json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))


def extract_host_port(line):
    line = clean_config_line(line)
    if len(line) > 8192:
        return None
    try:
        p = urlparse(line)
        if p.scheme in ("vless", "trojan"):
            if not p.hostname:
                return None
            return p.hostname, p.port or 443
        if p.scheme == "vmess":
            data = _b64_json(line[8:])
            add = data.get("add")
            if not add:
                return None
            return add, int(data.get("port", 443))
    except Exception:
        pass
    return None


def get_config_meta(line):
    line = clean_config_line(line)
    network, security, path = "tcp", "none", ""
    try:
        p = urlparse(line)
        if p.scheme in ("vless", "trojan"):
            q = parse_qs(p.query)
            network = q.get("type", ["tcp"])[0].lower()
            security = q.get("security", ["none"])[0].lower()
            path = q.get("path", [""])[0]
            if p.scheme == "trojan" and "security" not in q:
                security = "tls"
        elif p.scheme == "vmess":
            data = _b64_json(line[8:])
            network = str(data.get("net", "tcp")).lower()
            security = str(data.get("tls", "none")).lower()
            path = str(data.get("path", ""))
    except Exception:
        pass
    return network, security, path


def is_config_allowed(line):
    network, security, path = get_config_meta(line)
    if path and path in WS_PATH_BLOCKLIST:
        return False
    if security not in ("tls", "reality") and network != "grpc":
        return False
    return True


def _build_stream_settings(query, fallback_host):
    network = query.get("type", ["tcp"])[0] or "tcp"
    security = query.get("security", ["none"])[0] or "none"
    sni = query.get("sni", query.get("host", [fallback_host]))[0]
    fp = query.get("fp", [""])[0]
    stream = {"network": network}

    if security == "reality":
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "fingerprint": fp or "chrome",
            "serverName": sni,
            "publicKey": query.get("pbk", [""])[0],
            "shortId": query.get("sid", [""])[0],
            "spiderX": query.get("spx", [""])[0],
        }
    elif security == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": sni, "fingerprint": fp or "chrome", "allowInsecure": False}

    if network == "ws":
        stream["wsSettings"] = {"path": query.get("path", ["/"])[0],
                                "headers": {"Host": query.get("host", [sni])[0]}}
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": query.get("serviceName", [""])[0],
                                  "multiMode": query.get("mode", [""])[0] == "multi"}
    elif network in ("h2", "http"):
        stream["network"] = "h2"
        stream["httpSettings"] = {"path": query.get("path", ["/"])[0],
                                  "host": [query.get("host", [sni])[0]]}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": query.get("path", ["/"])[0],
                                   "host": query.get("host", [sni])[0]}
        if "mode" in query:
            stream["xhttpSettings"]["mode"] = query["mode"][0]
        if "extra" in query:
            try:
                stream["xhttpSettings"]["extra"] = json.loads(unquote(query["extra"][0]))
            except Exception:
                pass
    return stream


def parse_vless(line, tag):
    p = urlparse(line)
    q = parse_qs(p.query)
    user = {"id": p.username, "encryption": q.get("encryption", ["none"])[0] or "none"}
    if flow := q.get("flow", [""])[0]:
        user["flow"] = flow
    return {
        "tag": tag, "protocol": "vless",
        "settings": {"vnext": [{"address": p.hostname, "port": p.port or 443, "users": [user]}]},
        "streamSettings": _build_stream_settings(q, p.hostname),
    }


def parse_vmess(line, tag):
    data = _b64_json(line[8:].split("#")[0])
    net = data.get("net", "tcp")
    stream = {"network": net}
    if data.get("tls") == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {"serverName": data.get("sni") or data.get("host", ""), "allowInsecure": False}
    if net == "ws":
        stream["wsSettings"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", "")}}
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": data.get("path", "")}
    return {
        "tag": tag, "protocol": "vmess",
        "settings": {"vnext": [{"address": data.get("add"), "port": int(data.get("port", 443)),
                                "users": [{"id": data.get("id"), "alterId": int(data.get("aid", 0) or 0),
                                           "security": "auto"}]}]},
        "streamSettings": stream,
    }


def parse_trojan(line, tag):
    p = urlparse(line)
    q = parse_qs(p.query)
    if "security" not in q:
        q["security"] = ["tls"]
    return {
        "tag": tag, "protocol": "trojan",
        "settings": {"servers": [{"address": p.hostname, "port": p.port or 443, "password": p.username}]},
        "streamSettings": _build_stream_settings(q, p.hostname),
    }


def line_to_outbound(line, tag="test"):
    cleaned = clean_config_line(line)
    try:
        if cleaned.startswith("vless://"):
            return parse_vless(cleaned, tag)
        if cleaned.startswith("vmess://"):
            return parse_vmess(cleaned, tag)
        if cleaned.startswith("trojan://"):
            return parse_trojan(cleaned, tag)
    except Exception:
        pass
    return None


# ----------------------------------------------------------------------------
# Xray
# ----------------------------------------------------------------------------
def spawn_xray(outbound, socks_port):
    config = {
        "inbounds": [{"port": socks_port, "listen": "127.0.0.1", "protocol": "socks",
                      "settings": {"udp": False}}],
        "outbounds": [outbound],
        "log": {"loglevel": "none"},
    }
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            path = f.name
        proc = subprocess.Popen(["xray", "-config", path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        return proc, path
    except OSError:
        return None, None


def stop_xray(proc, path):
    if proc:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    if path and os.path.exists(path):
        try:
            os.unlink(path)
        except OSError:
            pass


# ----------------------------------------------------------------------------
# Чёрный список (сохраняется между запусками через кэш Actions)
# ----------------------------------------------------------------------------
def is_blacklisted(host, port):
    with blacklist_lock:
        ts = blacklist_dict.get((host, port))
        if ts is None:
            return False
        if int(time.time()) - ts > BLACKLIST_AGE_LIMIT:
            del blacklist_dict[(host, port)]
            return False
        return True


def add_to_blacklist(host, port):
    with blacklist_lock:
        if (host, port) in blacklist_dict:
            return
        blacklist_dict[(host, port)] = int(time.time())


def load_blacklist():
    blacklist_dict.clear()
    if not os.path.exists(BLACKLIST_FILE):
        return
    now = int(time.time())
    for line in _read_lines(BLACKLIST_FILE):
        parts = line.rsplit(":", 2)
        if len(parts) != 3:
            continue
        try:
            h, p, ts = parts[0], int(parts[1]), int(parts[2])
        except ValueError:
            continue
        if now - ts <= BLACKLIST_AGE_LIMIT:
            blacklist_dict[(h, p)] = ts


def save_blacklist():
    now = int(time.time())
    try:
        with blacklist_lock, open(BLACKLIST_FILE, "w") as f:
            for (h, p), ts in blacklist_dict.items():
                if now - ts <= BLACKLIST_AGE_LIMIT:
                    f.write(f"{h}:{p}:{ts}\n")
    except OSError:
        pass


# ----------------------------------------------------------------------------
# Проверки
# ----------------------------------------------------------------------------
def quick_reachability_check(line):
    """Фаза 1: TCP-пинг. Возвращает (line, ping_ms) или None."""
    original = line.strip()
    hp = extract_host_port(original)
    if not hp:
        return None
    host, port = hp
    if host in ("0.0.0.0", "127.0.0.1", "localhost") or port == 0:
        return None
    if is_ip_blacklisted(host) or is_blacklisted(host, port):
        return None
    ping = tcp_ping(host, port)
    if ping is None:
        add_to_blacklist(host, port)
        return None
    return original, ping


def test_single_config(line):
    """Фаза 2: реальный запрос через xray."""
    hp = extract_host_port(line)
    if not hp:
        return None
    host, port = hp
    outbound = line_to_outbound(line)
    if not outbound:
        return None
    socks_port = get_free_port()
    proc, cfg = spawn_xray(outbound, socks_port)
    if not proc:
        return None
    try:
        if not wait_for_port(socks_port):
            add_to_blacklist(host, port)
            return None
        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}
        success = 0
        for url in TEST_URLS:
            try:
                r = requests.get(url, proxies=proxies, timeout=TEST_TIMEOUT)
                if r.status_code in (200, 204):
                    success += 1
                    if success >= MIN_SUCCESS:
                        return line
            except requests.RequestException:
                continue
        add_to_blacklist(host, port)
        return None
    except Exception:
        add_to_blacklist(host, port)
        return None
    finally:
        stop_xray(proc, cfg)


def measure_speed(line):
    """Скорость в Мбит/с."""
    outbound = line_to_outbound(line)
    if not outbound:
        return 0.0
    socks_port = get_free_port()
    proc, cfg = spawn_xray(outbound, socks_port)
    if not proc:
        return 0.0
    try:
        if not wait_for_port(socks_port):
            return 0.0
        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}
        best = 0.0
        for url in SPEEDTEST_URLS:
            try:
                with requests.get(url, proxies=proxies, timeout=8, stream=True) as r:
                    if r.status_code != 200:
                        continue
                    downloaded = 0
                    start = time.perf_counter()
                    for chunk in r.iter_content(chunk_size=16384):
                        downloaded += len(chunk)
                        if time.perf_counter() - start > SPEEDTEST_TIMEOUT:
                            break
                    elapsed = time.perf_counter() - start
                    if elapsed > 0 and downloaded > 100_000:
                        best = max(best, (downloaded * 8 / 1_000_000) / elapsed)
                if best > 0:
                    break
            except requests.RequestException:
                continue
        return best
    except Exception:
        return 0.0
    finally:
        stop_xray(proc, cfg)


# ----------------------------------------------------------------------------
# Загрузка источников
# ----------------------------------------------------------------------------
LINK_RE = re.compile(r'(?:vless|vmess|trojan)://[^\s"\'<>]+')


def _extract_from_text(text):
    found = LINK_RE.findall(text)

    # JSON со вложенными base64-строками
    try:
        data = json.loads(text)

        def walk(o):
            if isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
            elif isinstance(o, str):
                if o.startswith(("vless://", "vmess://", "trojan://")):
                    found.append(o)
                else:
                    try:
                        clean = "".join(o.split())
                        if len(clean) > 20:
                            clean += "=" * (-len(clean) % 4)
                            found.extend(LINK_RE.findall(base64.b64decode(clean).decode("utf-8", errors="ignore")))
                    except Exception:
                        pass
        walk(data)
    except Exception:
        pass

    # вся страница в base64 (обычная подписка)
    try:
        clean = "".join(text.split())
        clean += "=" * (-len(clean) % 4)
        found.extend(LINK_RE.findall(base64.b64decode(clean).decode("utf-8", errors="ignore")))
    except Exception:
        pass
    return found


def fetch_configs_from_source(url):
    proxies = {"http": FETCH_PROXY, "https": FETCH_PROXY} if FETCH_PROXY else None
    text = ""
    for _ in range(3):
        try:
            with _session.get(url, timeout=(5, 15), stream=True, proxies=proxies) as r:
                if r.status_code != 200:
                    continue
                content, size, start = [], 0, time.time()
                for chunk in r.iter_content(chunk_size=65536):
                    if chunk:
                        content.append(chunk)
                        size += len(chunk)
                    if size > 8 * 1024 * 1024 or time.time() - start > 20:
                        break
                text = b"".join(content).decode("utf-8", errors="ignore").strip()
                if text:
                    break
        except requests.RequestException:
            time.sleep(1)
    if not text:
        return []

    seen, out = set(), []
    for line in _extract_from_text(text):
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def load_sources():
    for _ in range(3):
        try:
            resp = _session.get(SOURCES_LIST_URL, timeout=20)
            if resp.status_code == 200:
                srcs = []
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for part in line.split():
                        if part.startswith("http"):
                            srcs.append(part)
                if srcs:
                    return srcs
        except requests.RequestException:
            time.sleep(2)
    return []


def fetch_all_configs():
    sources = load_sources()
    if not sources:
        print("❌ Не удалось загрузить список источников.")
        sys.exit(1)
    print(f"✅ Источников: {len(sources)}")

    all_cfgs = []
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futs = {ex.submit(fetch_configs_from_source, s): s for s in sources}
        for fut in as_completed(futs):
            try:
                cfgs = fut.result()
            except Exception:
                cfgs = []
            print(f"{futs[fut]} → {len(cfgs)}")
            all_cfgs.extend(cfgs)

    print(f"🔄 Сырых конфигов: {len(all_cfgs)}. Дедупликация...")
    unique = {}
    for cfg in all_cfgs:
        hp = extract_host_port(cfg)
        if hp and hp not in unique:
            unique[hp] = cfg
    configs = list(unique.values())
    print(f"Уникальных: {len(configs)}")

    configs = [c for c in configs if not is_domain_blacklisted(c)]
    before = len(configs)
    configs = [c for c in configs if is_config_allowed(c)]
    print(f"🛡️ Отфильтровано без TLS/Reality: {before - len(configs)}. Осталось: {len(configs)}")
    random.shuffle(configs)
    return configs


# ----------------------------------------------------------------------------
# Публикация
# ----------------------------------------------------------------------------
def upload_to_github(content, file_path):
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{file_path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}
    for attempt in range(3):
        try:
            r = _session.get(url, headers=headers, params={"ref": BRANCH}, timeout=20)
            sha = r.json().get("sha") if r.status_code == 200 else None
            data = {
                "message": f"Update {datetime.now().isoformat(timespec='seconds')}",
                "content": base64.b64encode(content.encode()).decode(),
                "branch": BRANCH,
            }
            if sha:
                data["sha"] = sha
            put = _session.put(url, headers=headers, json=data, timeout=30)
            if put.status_code in (200, 201):
                print(f"✅ {file_path} обновлён")
                return True
            print(f"⚠️ GitHub API: {put.status_code} {put.text[:200]}")
        except requests.RequestException as e:
            print(f"⚠️ Ошибка загрузки: {e}")
        time.sleep(3)
    return False


# ----------------------------------------------------------------------------
# Основной процесс
# ----------------------------------------------------------------------------
def run():
    print(f"[{datetime.now()}] Старт")
    configs = fetch_all_configs()
    if not configs:
        print("⚠️ Нет конфигов.")
        return

    # Фаза 1: пинг
    print(f"Фаза 1/3: TCP-пинг {len(configs)} конфигов ({PING_WORKERS} потоков)...")
    alive = []
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futs = [ex.submit(quick_reachability_check, c) for c in configs]
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                alive.append(res)
            if i % 500 == 0 or i == len(futs):
                print(f"  {i}/{len(futs)}, живых: {len(alive)}")

    alive.sort(key=lambda x: x[1])
    alive = alive[:MAX_TO_TEST]
    line_ping = {l: p for l, p in alive}
    lines = [l for l, _ in alive]
    if not lines:
        print("⚠️ Нет живых серверов.")
        return

    # Фаза 2: xray
    print(f"Фаза 2/3: xray-тест {len(lines)} конфигов ({MAX_WORKERS} потоков)...")
    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(test_single_config, l) for l in lines]
        for i, fut in enumerate(as_completed(futs), 1):
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                working.append(res)
            if i % 25 == 0 or i == len(futs):
                print(f"  {i}/{len(futs)}, рабочих: {len(working)}")
    save_blacklist()
    print(f"Рабочих: {len(working)}")
    if not working:
        print("⚠️ Нет рабочих серверов.")
        return

    # Фаза 3: скорость
    print(f"Фаза 3/3: замер скорости ({SPEEDTEST_WORKERS} потоков)...")
    speeds = {}
    with ThreadPoolExecutor(max_workers=SPEEDTEST_WORKERS) as ex:
        futs = {ex.submit(measure_speed, l): l for l in working}
        for fut in as_completed(futs):
            try:
                speeds[futs[fut]] = fut.result()
            except Exception:
                speeds[futs[fut]] = 0.0

    # Страны
    prefetch_countries([extract_host_port(l)[0] for l in working if extract_host_port(l)])

    candidates = []
    for l in working:
        hp = extract_host_port(l)
        name, code = get_country(hp[0])
        if code in BLOCKED_COUNTRIES:
            continue
        if speeds.get(l, 0.0) >= MIN_SPEED:
            candidates.append((l, speeds[l], name, code))

    if not candidates:
        print(f"⚠️ Нет серверов со скоростью >= {MIN_SPEED} Мбит/с")
        return

    candidates.sort(key=lambda x: x[1], reverse=True)
    top_speed = candidates[0]
    rest = candidates[1:]
    best_ping = min(rest, key=lambda x: line_ping.get(x[0], 9999)) if rest else None
    ordered = [top_speed]
    if best_ping:
        ordered.append(best_ping)
        rest = [c for c in rest if c[0] != best_ping[0]]
    ordered.extend(rest)
    ordered = ordered[:MAX_FINAL]

    info = f" | 🚀 Top: ~{top_speed[1]:.1f} Mbps"
    if best_ping:
        info += f", ~{line_ping.get(best_ping[0], 0):.0f} ms"

    final = [
        f"#profile-title: {PANEL_TITLE}",
        "#profile-update-interval: 1",
        f"#subscription-userinfo: upload=0; download=0; total={TOTAL_BYTES}; expire={EXPIRE_TIMESTAMP}",
        f"#announce: 🔥 Серверов: {len(ordered)} | Обновлено: {datetime.now().strftime('%d.%m.%Y %H:%M')} | Подписывайтесь на {BRAND}{info}",
        f"#support-url: {TG_LINK}",
        f"#profile-web-page-url: {TG_LINK}",
    ]
    for line, _speed, name, code in ordered:
        flag = country_code_to_flag(code)
        title = f"{flag} {name or 'Unknown'} {BRAND}"
        base = re.sub(r"[#\s].*$", "", line).strip()
        final.append(f"{base}#{title}")

    upload_to_github("\n".join(final) + "\n", OUTPUT_FILE)


def main():
    if not GITHUB_TOKEN:
        print("❌ Не задана переменная GITHUB_TOKEN")
        sys.exit(1)
    try:
        subprocess.run(["xray", "-version"], capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        print("❌ xray не найден")
        sys.exit(1)

    load_blacklist()
    load_lists()
    run()


if __name__ == "__main__":
    main()
