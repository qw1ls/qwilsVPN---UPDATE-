#!/usr/bin/env python3
import base64
import datetime
import json
import os
import random
import re
import signal
import socket
import statistics
import subprocess
import tempfile
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Настройки и переменные окружения ---
SOURCES_LIST_URL = os.getenv(
    "SOURCES_LIST_URL",
    "https://raw.githubusercontent.com/qw1ls/qwilsVPN---UPDATE-/refs/heads/main/sources.txt",
)
RU_EGRESS_PROXY = os.getenv("RU_EGRESS_PROXY", "").strip()
RU_CHECK_URL = os.getenv("RU_CHECK_URL", "").strip()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "").strip()
BRANCH = os.getenv("BRANCH", "main").strip()

WORKING_OUTPUT = os.getenv("OUTPUT_FILE", "working_configs.txt").strip()
SUBSCRIPTION_OUTPUT = os.getenv("SUBSCRIPTION_FILE", "subscription.txt").strip()
BLACKLIST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "blacklist_local.txt")

PANEL_TITLE = "antiRKN FREE"
TAG_HANDLE = "@qw1lsVPN"
BLACKLIST_AGE_LIMIT = 5 * 3600

TIMEOUT_PER_URL = int(os.getenv("TIMEOUT_PER_URL", "7"))
MAX_TCP_PING_MS = float(os.getenv("MAX_TCP_PING_MS", "600"))
TCP_PING_TIMEOUT = MAX_TCP_PING_MS / 1000.0
SPEEDTEST_TIMEOUT = int(os.getenv("SPEEDTEST_TIMEOUT", "7"))
MIN_SPEED_MBPS = float(os.getenv("MIN_SPEED_MBPS", "1.0"))
MAX_SANE_SPEED_MBPS = float(os.getenv("MAX_SANE_SPEED_MBPS", "1000.0"))
MIN_SUCCESS = int(os.getenv("MIN_SUCCESS", "2"))

PING_WORKERS = int(os.getenv("PING_WORKERS", "35"))
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "10"))
FETCH_WORKERS = int(os.getenv("FETCH_WORKERS", "6"))
SPEEDTEST_WORKERS = int(os.getenv("SPEEDTEST_WORKERS", "8"))
XRAY_STARTUP_TIMEOUT = 2.5

TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://telegram.org",
    "https://www.instagram.com",
    "https://tiktok.com",
]
SPEEDTEST_URLS = [
    "https://raw.githubusercontent.com/BitDoctor/speed-test-file/refs/heads/master/5mb.txt",
    "https://speed.cloudflare.com/__down?bytes=5000000",
]
BLOCKED_COUNTRIES = {"JP", "VN", "AF", "IR", "TM", "CN", "KR"}

blacklist_dict: dict[tuple[str, int], int] = {}
blacklist_lock = Lock()
country_cache: dict[str, tuple[str, str]] = {}
dns_cache: dict[str, Optional[str]] = {}

_session = requests.Session()
_session.headers.update({"User-Agent": "Mozilla/5.0", "Connection": "close"})
_retry = Retry(total=2, backoff_factor=0.4, status_forcelist=[429, 500, 502, 503])
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=25, pool_maxsize=25)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)


def log(msg: str) -> None:
    print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def resolve_host(host: str) -> Optional[str]:
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
        dns_cache[host] = ip
        return ip
    except socket.gaierror:
        dns_cache[host] = None
        return None


def country_code_to_flag(code: str) -> str:
    if not code or len(code) != 2 or not code.isalpha():
        return "🌐"
    c = code.upper()
    return chr(ord(c[0]) + 0x1F1A5) + chr(ord(c[1]) + 0x1F1A5)


def _parse_ipapi_com(d: dict):
    if d.get("status") == "success":
        return d.get("country", "Unknown"), d.get("countryCode", "").upper()
    return None


def _parse_ipwho_is(d: dict):
    if d.get("country_code"):
        return d.get("country", "Unknown"), d.get("country_code", "").upper()
    return None


def _parse_freeipapi(d: dict):
    if d.get("countryCode"):
        return d.get("countryName", "Unknown"), d.get("countryCode", "").upper()
    return None


def get_country(host: str) -> tuple[str, str]:
    ip = resolve_host(host) or host
    if not ip:
        return "Unknown", ""
    if ip in country_cache:
        return country_cache[ip]

    providers = [
        (f"http://ip-api.com/json/{ip}?fields=status,country,countryCode", _parse_ipapi_com),
        (f"https://ipwho.is/{ip}", _parse_ipwho_is),
        (f"https://freeipapi.com/api/json/{ip}", _parse_freeipapi),
    ]
    random.shuffle(providers)
    for url, parser in providers:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                res = parser(r.json())
                if res and res[1]:
                    country_cache[ip] = res
                    return res
        except Exception:
            continue

    res = ("Unknown", "")
    country_cache[ip] = res
    return res


def prefetch_countries_batch(hosts: list[str]) -> None:
    unique_hosts = list({h for h in hosts if h})
    if not unique_hosts:
        return
    log(f"Определение локаций ({len(unique_hosts)} серверов)...")
    with ThreadPoolExecutor(max_workers=20) as ex:
        list(ex.map(get_country, unique_hosts))


# --- Чёрный список ---
def load_blacklist() -> None:
    global blacklist_dict
    blacklist_dict = {}
    if not os.path.exists(BLACKLIST_FILE):
        return
    now = int(time.time())
    try:
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.rsplit(":", 2)
                if len(parts) != 3:
                    continue
                h, p, ts = parts
                try:
                    p_int, ts_int = int(p), int(ts)
                except ValueError:
                    continue
                if now - ts_int <= BLACKLIST_AGE_LIMIT:
                    blacklist_dict[(h, p_int)] = ts_int
    except OSError:
        pass


def is_blacklisted(host: str, port: int) -> bool:
    with blacklist_lock:
        ts = blacklist_dict.get((host, port))
        if ts is None:
            return False
        if int(time.time()) - ts > BLACKLIST_AGE_LIMIT:
            del blacklist_dict[(host, port)]
            return False
        return True


def add_to_blacklist_local(host: str, port: int) -> None:
    key = (host, port)
    with blacklist_lock:
        if key in blacklist_dict:
            return
        blacklist_dict[key] = int(time.time())
    try:
        with open(BLACKLIST_FILE, "a", encoding="utf-8") as f:
            f.write(f"{host}:{port}:{int(time.time())}\n")
    except OSError:
        pass


def save_blacklist() -> None:
    now = int(time.time())
    with blacklist_lock:
        snapshot = {k: ts for k, ts in blacklist_dict.items() if now - ts <= BLACKLIST_AGE_LIMIT}
    try:
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            for (h, p), ts in sorted(snapshot.items()):
                f.write(f"{h}:{p}:{ts}\n")
    except OSError:
        pass


# --- Парсинг конфигов (vless / vmess / trojan) ---
def clean_config_line(line: str) -> str:
    return re.split(r"[#\s]", line.strip(), maxsplit=1)[0].strip()


def extract_host_port(line: str) -> Optional[tuple[str, int]]:
    cleaned = clean_config_line(line)
    if not cleaned or len(cleaned) > 8192:
        return None
    try:
        p = urllib.parse.urlparse(cleaned)
        if p.scheme in ("vless", "trojan"):
            if not p.hostname:
                return None
            return p.hostname, int(p.port or 443)
        if p.scheme == "vmess":
            b64 = cleaned[8:]
            if not b64:
                return None
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            add = data.get("add")
            if not add:
                return None
            return str(add), int(data.get("port", 443))
    except Exception:
        pass
    return None


def _build_stream_settings(query: dict, fallback_host: str) -> dict:
    network = (query.get("type", ["tcp"])[0] or "tcp").lower()
    security = (query.get("security", ["none"])[0] or "none").lower()
    sni = query.get("sni", query.get("host", [fallback_host]))[0]
    fp = query.get("fp", [""])[0]
    stream: dict = {"network": network}

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
        stream["tlsSettings"] = {
            "serverName": sni,
            "fingerprint": fp or "chrome",
            "allowInsecure": False,
        }

    if network == "ws":
        stream["wsSettings"] = {
            "path": query.get("path", ["/"])[0],
            "headers": {"Host": query.get("host", [sni])[0]},
        }
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": query.get("serviceName", [""])[0],
            "multiMode": query.get("mode", [""])[0] == "multi",
        }
    elif network in ("h2", "http"):
        stream["network"] = "h2"
        stream["httpSettings"] = {
            "path": query.get("path", ["/"])[0],
            "host": [query.get("host", [sni])[0]],
        }
    elif network == "xhttp":
        stream["xhttpSettings"] = {
            "path": query.get("path", ["/"])[0],
            "host": query.get("host", [sni])[0],
        }
        if "mode" in query:
            stream["xhttpSettings"]["mode"] = query["mode"][0]
        if "extra" in query:
            try:
                stream["xhttpSettings"]["extra"] = json.loads(urllib.parse.unquote(query["extra"][0]))
            except Exception:
                pass

    return stream


def parse_vless_to_outbound(line: str, tag: str) -> dict:
    p = urllib.parse.urlparse(line)
    query = urllib.parse.parse_qs(p.query)
    user: dict = {"id": urllib.parse.unquote(p.username or ""), "encryption": "none"}
    if flow := query.get("flow", [""])[0]:
        user["flow"] = flow
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [{"address": p.hostname, "port": int(p.port or 443), "users": [user]}]
        },
        "streamSettings": _build_stream_settings(query, p.hostname or ""),
    }


def parse_vmess_to_outbound(line: str, tag: str) -> dict:
    b64 = line[8:].split("#")[0]
    b64 += "=" * (-len(b64) % 4)
    data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
    net = str(data.get("net", "tcp")).lower()
    stream: dict = {"network": net}
    if data.get("tls") == "tls":
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": data.get("sni") or data.get("host", ""),
            "allowInsecure": False,
        }
    if net == "ws":
        stream["wsSettings"] = {
            "path": data.get("path", "/"),
            "headers": {"Host": data.get("host", "")},
        }
    elif net == "grpc":
        stream["grpcSettings"] = {"serviceName": data.get("path", "")}
    return {
        "tag": tag,
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


def parse_trojan_to_outbound(line: str, tag: str) -> dict:
    p = urllib.parse.urlparse(line)
    query = urllib.parse.parse_qs(p.query)
    if "security" not in query:
        query["security"] = ["tls"]
    return {
        "tag": tag,
        "protocol": "trojan",
        "settings": {
            "servers": [
                {
                    "address": p.hostname,
                    "port": int(p.port or 443),
                    "password": urllib.parse.unquote(p.username or ""),
                }
            ]
        },
        "streamSettings": _build_stream_settings(query, p.hostname or ""),
    }


def _line_to_outbound(line: str, tag: str = "test") -> Optional[dict]:
    cleaned = clean_config_line(line)
    try:
        if cleaned.startswith("vless://"):
            return parse_vless_to_outbound(cleaned, tag)
        if cleaned.startswith("vmess://"):
            return parse_vmess_to_outbound(cleaned, tag)
        if cleaned.startswith("trojan://"):
            return parse_trojan_to_outbound(cleaned, tag)
    except Exception:
        pass
    return None


# --- Сеть и Xray ---
def tcp_ping(host: str, port: int) -> Optional[float]:
    try:
        start = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(TCP_PING_TIMEOUT)
            sock.connect((host, port))
            return (time.perf_counter() - start) * 1000.0
    except OSError:
        return None


def get_free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def wait_for_port(port: int, timeout: float = XRAY_STARTUP_TIMEOUT) -> bool:
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


def _spawn_xray(outbound: dict, socks_port: int):
    config = {
        "inbounds": [{"port": socks_port, "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [outbound],
        "log": {"loglevel": "warning"},
    }
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f, indent=2)
            path = f.name
        proc = subprocess.Popen(
            ["xray", "-config", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        return proc, path
    except OSError:
        return None, None


def _stop_xray(proc, path) -> None:
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


def quick_reachability_check(line: str) -> Optional[str]:
    original = line.strip()
    hp = extract_host_port(original)
    if not hp:
        return None
    host, port = hp
    if host in ("0.0.0.0", "127.0.0.1", "localhost") or port == 0:
        return None
    if is_blacklisted(host, port):
        return None
    ping = tcp_ping(host, port)
    if ping is None or ping > MAX_TCP_PING_MS:
        add_to_blacklist_local(host, port)
        return None
    return original


def test_single_config(line: str):
    original = line.strip()
    hp = extract_host_port(original)
    if not hp:
        return None
    host, port = hp
    if host in ("0.0.0.0", "127.0.0.1", "localhost") or port == 0:
        return None
    if is_blacklisted(host, port):
        return None

    outbound = _line_to_outbound(original)
    if not outbound:
        return None

    socks_port = get_free_port()
    proc, cfg = _spawn_xray(outbound, socks_port)
    if not proc:
        return None

    try:
        if not wait_for_port(socks_port):
            add_to_blacklist_local(host, port)
            return None

        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }

        if RU_CHECK_URL:
            try:
                r_ru = requests.get(RU_CHECK_URL, proxies=proxies, timeout=TIMEOUT_PER_URL)
                if r_ru.status_code >= 500:
                    add_to_blacklist_local(host, port)
                    return None
            except requests.RequestException:
                add_to_blacklist_local(host, port)
                return None

        success = 0
        for url in TEST_URLS:
            try:
                r = requests.get(url, proxies=proxies, timeout=TIMEOUT_PER_URL)
                if r.status_code in (200, 204):
                    success += 1
                    if success >= MIN_SUCCESS:
                        return original, host
            except requests.RequestException:
                continue

        add_to_blacklist_local(host, port)
        return None
    except Exception:
        add_to_blacklist_local(host, port)
        return None
    finally:
        _stop_xray(proc, cfg)


def measure_speed_multi(line: str) -> float:
    outbound = _line_to_outbound(line)
    if not outbound:
        return 0.0
    socks_port = get_free_port()
    proc, cfg = _spawn_xray(outbound, socks_port)
    if not proc:
        return 0.0
    try:
        if not wait_for_port(socks_port):
            return 0.0
        proxies = {
            "http": f"socks5h://127.0.0.1:{socks_port}",
            "https": f"socks5h://127.0.0.1:{socks_port}",
        }
        run_speeds: list[float] = []
        for url in SPEEDTEST_URLS:
            try:
                with requests.get(url, proxies=proxies, timeout=SPEEDTEST_TIMEOUT, stream=True) as r:
                    if r.status_code != 200:
                        continue
                    downloaded = 0
                    start = time.perf_counter()
                    for chunk in r.iter_content(chunk_size=32768):
                        if not chunk:
                            break
                        downloaded += len(chunk)
                        elapsed = time.perf_counter() - start
                        if elapsed >= SPEEDTEST_TIMEOUT or downloaded >= 4 * 1024 * 1024:
                            break
                    elapsed = time.perf_counter() - start
                    if downloaded >= 65536 and elapsed >= 0.25:
                        mbps = (downloaded * 8.0) / (elapsed * 1_000_000.0)
                        if 0.0 < mbps <= MAX_SANE_SPEED_MBPS:
                            run_speeds.append(mbps)
            except requests.RequestException:
                continue

        if not run_speeds:
            return 0.0
        return round(statistics.median(run_speeds), 1)
    except Exception:
        return 0.0
    finally:
        _stop_xray(proc, cfg)


# --- Загрузка источников ---
def fetch_configs_from_source(url: str) -> list[str]:
    text = ""
    proxies = {"http": RU_EGRESS_PROXY, "https": RU_EGRESS_PROXY} if RU_EGRESS_PROXY else None
    try:
        with _session.get(url, timeout=(5, 10), stream=True, proxies=proxies) as r:
            if r.status_code == 200:
                content, downloaded, start_time = [], 0, time.time()
                for chunk in r.iter_content(chunk_size=65536):
                    if chunk:
                        content.append(chunk)
                        downloaded += len(chunk)
                    if downloaded > 5 * 1024 * 1024 or (time.time() - start_time) > 15:
                        break
                text = b"".join(content).decode("utf-8", errors="ignore").strip()
    except requests.RequestException:
        return []

    if not text:
        return []

    found_lines = []
    found_lines.extend(re.findall(r"(?:vless|vmess|trojan)://[^\s\"'<>]+", text))

    try:
        clean_b64 = "".join(text.split())
        padded = clean_b64 + "=" * (-len(clean_b64) % 4)
        decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
        found_lines.extend(re.findall(r"(?:vless|vmess|trojan)://[^\s\"'<>]+", decoded))
    except Exception:
        pass

    unique_lines = []
    seen = set()
    for line in found_lines:
        line = line.strip()
        if line not in seen:
            seen.add(line)
            unique_lines.append(line)
    return unique_lines


def get_sources() -> list[str]:
    resp = _session.get(SOURCES_LIST_URL, timeout=15)
    resp.raise_for_status()
    urls = []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for part in line.split():
            if part and not part.startswith("#"):
                urls.append(part.strip())
    log(f"Загружено {len(urls)} источников из {SOURCES_LIST_URL}")
    return urls


def fetch_all_configs_dedup() -> list[str]:
    all_cfgs = []
    source_list = get_sources()
    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as ex:
        futures = {ex.submit(fetch_configs_from_source, src): src for src in source_list}
        for future in as_completed(futures):
            src = futures[future]
            try:
                cfgs = future.result()
            except Exception:
                cfgs = []
            log(f"{src} -> {len(cfgs)} конфигов")
            all_cfgs.extend(cfgs)

    log(f"Собрано {len(all_cfgs)} сырых конфигов. Удаляем дубликаты...")
    unique: dict[tuple[str, int], str] = {}
    for cfg in all_cfgs:
        hp = extract_host_port(cfg)
        if hp and hp not in unique:
            unique[hp] = cfg
    configs = list(unique.values())
    log(f"Уникальных конфигов: {len(configs)}")
    return configs


def rename_config_with_label(line: str, label: str) -> str:
    cleaned = clean_config_line(line)
    if cleaned.lower().startswith("vmess://"):
        b64 = cleaned[8:]
        b64 += "=" * (-len(b64) % 4)
        try:
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            data["ps"] = label
            new_b64 = base64.b64encode(
                json.dumps(data, ensure_ascii=False).encode("utf-8")
            ).decode("utf-8")
            return f"vmess://{new_b64}"
        except Exception:
            pass
    return f"{cleaned}#{urllib.parse.quote(label)}"


def upload_to_github_with_retry(content: str, file_path: str) -> bool:
    if not GITHUB_TOKEN or not GITHUB_REPOSITORY:
        return False
    url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/contents/{file_path}"
    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    try:
        r = _session.get(url, headers=headers, timeout=15)
        sha = r.json().get("sha") if r.status_code == 200 else None
        data = {
            "message": f"Update {file_path} ({datetime.datetime.now().isoformat()})",
            "content": base64.b64encode(content.encode("utf-8")).decode("utf-8"),
            "branch": BRANCH,
        }
        if sha:
            data["sha"] = sha
        put = _session.put(url, headers=headers, json=data, timeout=25)
        if put.status_code in (200, 201):
            log(f"{file_path} обновлён через GitHub API")
            return True
    except requests.RequestException:
        pass
    return False


def main() -> None:
    load_blacklist()
    log(f"Чёрный список: {len(blacklist_dict)}")

    configs = fetch_all_configs_dedup()
    total = len(configs)
    log(f"Фаза 1/2: TCP-пинг ({PING_WORKERS} потоков) для {total} конфигов...")

    alive = []
    with ThreadPoolExecutor(max_workers=PING_WORKERS) as ex:
        futures = {ex.submit(quick_reachability_check, c): c for c in configs}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                res = future.result()
            except Exception:
                res = None
            if res:
                alive.append(res)
            if i % 250 == 0 or i == total:
                log(f"  пинг: {i}/{total}, живых: {len(alive)}")

    log(f"Фаза 2/2: Xray-тест ({len(alive)} конфигов, {MAX_WORKERS} потоков)...")
    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(test_single_config, c): c for c in alive}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                res = future.result()
            except Exception:
                res = None
            if res:
                working.append(res[0])
            if i % 50 == 0 or i == len(alive):
                log(f"  xray-тест: {i}/{len(alive)}, рабочих: {len(working)}")

    log(f"Рабочих по Xray: {len(working)} из {total}")
    save_blacklist()

    if not working:
        log("Рабочих серверов не найдено.")
        return

    log(f"Замер скорости ({len(working)} серверов, {SPEEDTEST_WORKERS} потоков)...")
    speeds: list[tuple[str, float]] = []
    with ThreadPoolExecutor(max_workers=SPEEDTEST_WORKERS) as ex:
        futures = {ex.submit(measure_speed_multi, line): line for line in working}
        done_spd = 0
        for future in as_completed(futures):
            done_spd += 1
            line = futures[future]
            try:
                spd = future.result()
            except Exception:
                spd = 0.0
            speeds.append((line, spd))
            if done_spd % 50 == 0 or done_spd == len(working):
                log(f"  скорость: {done_spd}/{len(working)}")

    hosts = [hp[0] for line, _ in speeds if (hp := extract_host_port(line))]
    prefetch_countries_batch(hosts)

    ranked: list[tuple[float, str]] = []
    for line, spd in speeds:
        if spd < MIN_SPEED_MBPS:
            continue
        hp = extract_host_port(line)
        country_name, country_code = get_country(hp[0]) if hp else ("Unknown", "")
        if country_code in BLOCKED_COUNTRIES:
            continue
        flag = country_code_to_flag(country_code)
        label = f"{flag} {country_name} | {spd:.1f} Mbps | {TAG_HANDLE}"
        renamed = rename_config_with_label(line, label)
        ranked.append((spd, renamed))

    ranked.sort(key=lambda x: x[0], reverse=True)
    final_configs = [item[1] for item in ranked]

    if final_configs:
        header = f"#profile-title: {PANEL_TITLE}"
        plain_text = "\n".join([header] + final_configs) + "\n"
        with open(WORKING_OUTPUT, "w", encoding="utf-8") as f:
            f.write(plain_text)

        b64_sub = base64.b64encode(plain_text.encode("utf-8")).decode("utf-8") + "\n"
        with open(SUBSCRIPTION_OUTPUT, "w", encoding="utf-8") as f:
            f.write(b64_sub)

        upload_to_github_with_retry(plain_text, WORKING_OUTPUT)
        upload_to_github_with_retry(b64_sub, SUBSCRIPTION_OUTPUT)
        log(f"Готово! Сохранено серверов: {len(final_configs)} | Топ скорость: {ranked[0][0]:.1f} Mbps")
    else:
        log(f"Ни один сервер не прошёл порог скорости >= {MIN_SPEED_MBPS} Mbps.")


if __name__ == "__main__":
    main()
