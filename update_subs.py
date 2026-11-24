
from __future__ import annotations

import base64
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from queue import Queue as QueuePort
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.error import URLError
from urllib.request import Request, urlopen

TEST_URL = "https://ya.ru"
TEST_URLS = [
    "https://ya.ru",
    "https://www.vk.com",
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
]

TEST_TIMEOUT = 8
SOCKS_PORT_MIN = 20000
SOCKS_PORT_MAX = 29999
PORT_POOL_SIZE = 64
BATCH_SAVE_EVERY = 10
BRAND_TAG = "@qw1lsVPN"

URI_REGEX = re.compile(r'(?:vless|vmess|trojan)://[^\s"\'<>`]+', re.IGNORECASE)

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

_country_cache: dict[str, tuple[str, str]] = {}


def find_xray() -> str | None:
    """Locate xray executable in PATH or common local folders."""
    exe_name = "xray.exe" if sys.platform == "win32" else "xray"
    found = shutil.which(exe_name)
    if found:
        return found
    here = Path(__file__).resolve().parent
    for folder in (here, Path("."), Path.home() / "xray", Path("/usr/local/bin")):
        candidate = folder / exe_name
        if candidate.is_file():
            return str(candidate)
    return None


def _b64_decode_text(s: str) -> str:
    cleaned = "".join(s.strip().split()).replace("-", "+").replace("_", "/")
    pad = len(cleaned) % 4
    if pad:
        cleaned += "=" * (4 - pad)
    return base64.b64decode(cleaned, validate=False).decode("utf-8", errors="ignore")


def decode_subscription(source: str) -> list[str]:
    """Extract vmess://, vless://, and trojan:// links from plain text or base64."""
    if not source:
        return []
    links: list[str] = []
    seen: set[str] = set()

    for m in URI_REGEX.findall(source):
        u = m.strip()
        if u and u not in seen:
            seen.add(u)
            links.append(u)

    if not links:
        try:
            decoded = _b64_decode_text(source)
            for m in URI_REGEX.findall(decoded):
                u = m.strip()
                if u and u not in seen:
                    seen.add(u)
                    links.append(u)
        except Exception:
            pass

    return links


def parse_json_subscription(source: str) -> list[tuple[str, dict]] | None:
    """Parse a JSON array of full Xray configs if source is a JSON config list."""
    stripped = source.strip()
    if not stripped.startswith("["):
        return None
    try:
        data = json.loads(stripped)
    except Exception:
        return None
    if not isinstance(data, list):
        return None

    out: list[tuple[str, dict]] = []
    for idx, item in enumerate(data):
        if isinstance(item, dict) and isinstance(item.get("outbounds"), list):
            remark = str(item.get("remark") or item.get("remarks") or f"JSON-Node-{idx + 1}")[:50]
            out.append((remark, item))
    return out or None


def get_proxy_outbound_from_config(cfg: dict) -> dict | None:
    for ob in cfg.get("outbounds") or []:
        if isinstance(ob, dict) and ob.get("protocol") in ("vless", "vmess", "trojan"):
            return ob
    return None


def get_outbound_server_port(outbound: dict) -> tuple[str, int] | None:
    try:
        proto = outbound.get("protocol")
        settings = outbound.get("settings") or {}
        if proto in ("vless", "vmess"):
            vnext = settings.get("vnext") or []
            if vnext:
                srv = vnext[0]
                return str(srv["address"]).lower(), int(srv.get("port", 443))
        elif proto == "trojan":
            servers = settings.get("servers") or []
            if servers:
                srv = servers[0]
                return str(srv["address"]).lower(), int(srv.get("port", 443))
    except Exception:
        return None
    return None


def build_test_config_from_json(full_config: dict, socks_port: int) -> dict:
    proxy_ob = get_proxy_outbound_from_config(full_config)
    if proxy_ob is None:
        return build_xray_config({}, socks_port)
    return build_xray_config(proxy_ob, socks_port)


def _outbound_to_link(outbound: dict, remark: str) -> str | None:
    """Best-effort conversion from outbound back to shareable URI."""
    try:
        proto = outbound.get("protocol")
        settings = outbound.get("settings") or {}
        stream = outbound.get("streamSettings") or {}
        net = stream.get("network") or "tcp"
        sec = stream.get("security") or "none"
        tag = quote(remark) if remark else ""

        if proto == "vless":
            vnext = (settings.get("vnext") or [])[0]
            user = (vnext.get("users") or [])[0]
            host = vnext["address"]
            port = int(vnext.get("port", 443))
            uid = quote(str(user["id"]))
            params: list[str] = [f"encryption={quote(str(user.get('encryption') or 'none'))}", f"type={quote(str(net))}"]
            if user.get("flow"):
                params.append(f"flow={quote(str(user['flow']))}")
            params.append(f"security={quote(str(sec))}")

            if sec == "reality":
                rc = stream.get("realitySettings") or {}
                if rc.get("serverName"):
                    params.append(f"sni={quote(str(rc['serverName']))}")
                if rc.get("fingerprint"):
                    params.append(f"fp={quote(str(rc['fingerprint']))}")
                if rc.get("publicKey"):
                    params.append(f"pbk={quote(str(rc['publicKey']))}")
                if rc.get("shortId"):
                    params.append(f"sid={quote(str(rc['shortId']))}")
                if rc.get("spiderX"):
                    params.append(f"spx={quote(str(rc['spiderX']))}")
            elif sec == "tls":
                tc = stream.get("tlsSettings") or {}
                if tc.get("serverName"):
                    params.append(f"sni={quote(str(tc['serverName']))}")
                if tc.get("fingerprint"):
                    params.append(f"fp={quote(str(tc['fingerprint']))}")
                if tc.get("alpn"):
                    params.append(f"alpn={quote(','.join(tc['alpn']))}")

            if net == "ws":
                wc = stream.get("wsSettings") or {}
                if wc.get("path"):
                    params.append(f"path={quote(str(wc['path']))}")
                hdr_host = (wc.get("headers") or {}).get("Host")
                if hdr_host:
                    params.append(f"host={quote(str(hdr_host))}")
            elif net == "grpc":
                gc = stream.get("grpcSettings") or {}
                if gc.get("serviceName"):
                    params.append(f"serviceName={quote(str(gc['serviceName']))}")

            q_str = "&".join(params)
            return f"vless://{uid}@{host}:{port}?{q_str}#{tag}"

        if proto == "trojan":
            srv = (settings.get("servers") or [])[0]
            host = srv["address"]
            port = int(srv.get("port", 443))
            pwd = quote(str(srv["password"]))
            params = [f"type={quote(str(net))}", f"security={quote(str(sec))}"]
            tc = stream.get("tlsSettings") or {}
            if tc.get("serverName"):
                params.append(f"sni={quote(str(tc['serverName']))}")
            if tc.get("fingerprint"):
                params.append(f"fp={quote(str(tc['fingerprint']))}")
            if net == "ws":
                wc = stream.get("wsSettings") or {}
                if wc.get("path"):
                    params.append(f"path={quote(str(wc['path']))}")
                hdr_host = (wc.get("headers") or {}).get("Host")
                if hdr_host:
                    params.append(f"host={quote(str(hdr_host))}")
            elif net == "grpc":
                gc = stream.get("grpcSettings") or {}
                if gc.get("serviceName"):
                    params.append(f"serviceName={quote(str(gc['serviceName']))}")
            return f"trojan://{pwd}@{host}:{port}?{'&'.join(params)}#{tag}"

        if proto == "vmess":
            vnext = (settings.get("vnext") or [])[0]
            user = (vnext.get("users") or [])[0]
            wc = stream.get("wsSettings") or {}
            gc = stream.get("grpcSettings") or {}
            tc = stream.get("tlsSettings") or {}
            payload = {
                "v": "2",
                "ps": remark or "VMess",
                "add": vnext["address"],
                "port": int(vnext.get("port", 443)),
                "id": user["id"],
                "aid": int(user.get("alterId", 0) or 0),
                "scy": user.get("security") or "auto",
                "net": net,
                "type": "none",
                "host": (wc.get("headers") or {}).get("Host") or tc.get("serverName") or "",
                "path": wc.get("path") or gc.get("serviceName") or "/",
                "tls": "tls" if sec == "tls" else "",
                "sni": tc.get("serverName") or "",
            }
            b64 = base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii")
            return f"vmess://{b64}"
    except Exception:
        return None
    return None


def _build_stream(
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
) -> dict:
    ns = net.lower() if net.lower() in ("tcp", "ws", "grpc", "http", "h2") else "tcp"
    sec = security.lower()
    if sec == "none" and pbk:
        sec = "reality"

    stream: dict = {"network": ns}
    if sec == "reality" and pbk:
        stream["security"] = "reality"
        rc: dict = {
            "serverName": sni or host or "www.google.com",
            "fingerprint": fp or "chrome",
            "publicKey": pbk,
            "shortId": sid or "",
        }
        if spx:
            rc["spiderX"] = spx
        stream["realitySettings"] = rc
    elif sec == "tls":
        tc: dict = {
            "serverName": sni or host,
            "fingerprint": fp or "chrome",
            "allowInsecure": True,
        }
        if alpn:
            tc["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        stream["security"] = "tls"
        stream["tlsSettings"] = tc
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


def parse_vmess(link: str) -> dict | None:
    try:
        data = json.loads(_b64_decode_text(link[8:]))
        addr = str(data.get("add") or data.get("address") or "").strip()
        uid = str(data.get("id") or data.get("uuid") or "").strip()
        if not addr or not uid:
            return None
        port = int(data.get("port", 443))
        tls_on = str(data.get("tls", "")).strip().lower() in ("1", "true", "tls", "yes")
        sni = str(data.get("sni") or data.get("host") or addr).strip()
        host_h = str(data.get("host") or sni).strip()
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
            "streamSettings": _build_stream(
                net=str(data.get("net") or "tcp"),
                security="tls" if tls_on else "none",
                sni=sni,
                fp=str(data.get("fp") or "chrome"),
                alpn=str(data.get("alpn") or ""),
                path=str(data.get("path") or "/"),
                host=host_h,
            ),
        }
    except Exception:
        return None


def parse_vless(link: str) -> dict | None:
    try:
        base = link.split("#", 1)[0].strip()
        parsed = urlparse(base)
        if "@" not in parsed.netloc:
            return None
        uid_raw, host_port = parsed.netloc.rsplit("@", 1)
        uid = unquote(uid_raw).strip()
        if ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            port = int(port_s)
        else:
            host, port = host_port, 443
        if not uid or not host:
            return None
        q = parse_qs(parsed.query)
        get = lambda k, d="": unquote((q.get(k) or [d])[0]).strip()
        user: dict = {"id": uid, "encryption": get("encryption", "none") or "none"}
        if flow := get("flow"):
            user["flow"] = flow
        return {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
            "streamSettings": _build_stream(
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
            ),
        }
    except Exception:
        return None


def parse_trojan(link: str) -> dict | None:
    try:
        base = link.split("#", 1)[0].strip()
        parsed = urlparse(base)
        if "@" not in parsed.netloc:
            return None
        pwd_raw, host_port = parsed.netloc.rsplit("@", 1)
        pwd = unquote(pwd_raw).strip()
        if ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            port = int(port_s)
        else:
            host, port = host_port, 443
        if not pwd or not host:
            return None
        q = parse_qs(parsed.query)
        get = lambda k, d="": unquote((q.get(k) or [d])[0]).strip()
        srv: dict = {"address": host, "port": port, "password": pwd}
        if flow := get("flow"):
            srv["flow"] = flow
        return {
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {"servers": [srv]},
            "streamSettings": _build_stream(
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
            ),
        }
    except Exception:
        return None


def parse_link(link: str) -> dict | None:
    """Parse one proxy link into Xray outbound, or None if unsupported."""
    link = link.strip()
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("vless://"):
        return parse_vless(link)
    if link.startswith("trojan://"):
        return parse_trojan(link)
    return None


def build_xray_config(outbound: dict, socks_port: int) -> dict:
    """Full Xray config: SOCKS inbound + proxy outbound + direct fallback."""
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


def _flag_from_code(cc: str) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌍"
    cc = cc.upper()
    return chr(ord(cc[0]) + 0x1F1A5) + chr(ord(cc[1]) + 0x1F1A5)


def resolve_country_ru(host: str) -> tuple[str, str]:
    """Resolve (flag, Russian country name) for a hostname or IPv4 address."""
    if not host:
        return ("🌍", "Сервер")
    if host in _country_cache:
        return _country_cache[host]
    try:
        ip = host
        try:
            socket.inet_aton(host)
        except OSError:
            ip = socket.gethostbyname(host)

        import requests

        for url in (
            f"http://ip-api.com/json/{ip}?fields=status,countryCode,country",
            f"https://ipwho.is/{ip}",
        ):
            try:
                r = requests.get(url, timeout=2.0)
                if not r.ok:
                    continue
                data = r.json()
                cc = (data.get("countryCode") or data.get("country_code") or "").upper()
                if cc == "UK":
                    cc = "GB"
                if cc in COUNTRY_MAP:
                    res = COUNTRY_MAP[cc]
                    _country_cache[host] = res
                    return res
                if len(cc) == 2 and cc.isalpha():
                    cname = (data.get("country") or cc).strip()
                    res = (_flag_from_code(cc), cname)
                    _country_cache[host] = res
                    return res
            except Exception:
                continue
    except Exception:
        pass

    res = ("🌍", "Сервер")
    _country_cache[host] = res
    return res


def format_qwils_remark(host: str, ping_ms: float, fallback_remark: str = "") -> str:
    flag, country_name = resolve_country_ru(host)
    ms_int = max(1, int(round(ping_ms)))
    base_name = f"{flag} {country_name}"
    if fallback_remark and any(k in fallback_remark.lower() for k in ("white", "wl", "бел", "mobile", "lte", "4g", "5g")):
        base_name = f"🇪🇺 white list ({fallback_remark[:24]})"
    return f"{base_name} [{ms_int}ms] {BRAND_TAG}"


def apply_remark_to_link(link: str, new_remark: str) -> str:
    base_link = link.split("#", 1)[0].strip()
    return f"{base_link}#{quote(new_remark)}"


def run_xray_and_test(config_path: str, socks_port: int, timeout: int = TEST_TIMEOUT) -> tuple[bool, str, float]:
    """
    Run Xray with config and test real traffic through local SOCKS5 proxy.
    Returns (success, result_str, ping_ms). ping_ms is -1 on failure.
    """
    creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    xray_path = find_xray()
    if not xray_path:
        return (False, "xray not found", -1.0)

    proc = subprocess.Popen(
        [xray_path, "run", "-config", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )

    def fail(result_str: str) -> tuple[bool, str, float]:
        return (False, result_str, -1.0)

    req_timeout = max(1.5, float(timeout) - 1.5)

    try:
        time.sleep(0.8)
        if proc.poll() is not None:
            return fail("xray exited")

        proxy_url = f"socks5://127.0.0.1:{socks_port}"
        proxies = {"http": proxy_url, "https": proxy_url}

        try:
            import requests

            last_err = "no connection"
            for test_url in TEST_URLS:
                t0 = time.perf_counter()
                try:
                    r = requests.get(test_url, proxies=proxies, timeout=req_timeout)
                    ping_ms = (time.perf_counter() - t0) * 1000.0
                    if r.status_code in (200, 204, 301, 302):
                        return (True, str(r.status_code), ping_ms)
                    last_err = f"HTTP {r.status_code}"
                except requests.exceptions.Timeout:
                    last_err = "timeout"
                except requests.exceptions.ProxyError:
                    last_err = "proxy error"
                except requests.exceptions.ConnectionError:
                    last_err = "connection failed"
                except Exception as e:
                    last_err = type(e).__name__

            return fail(last_err)
        except ImportError:
            try:
                import socks

                t0 = time.perf_counter()
                sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(req_timeout)
                sock.setproxy(socks.SOCKS5, "127.0.0.1", socks_port)
                sock.connect(("ya.ru", 443))
                ping_ms = (time.perf_counter() - t0) * 1000.0
                sock.close()
                return (True, "OK", ping_ms)
            except Exception:
                return fail("no connection")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def get_remark(link: str) -> str:
    """Extract remark/name from link (e.g. after # in vless/trojan or ps in vmess)."""
    if "#" in link:
        return unquote(link.split("#", 1)[1].strip()[:50])
    if link.startswith("vmess://"):
        try:
            o = json.loads(_b64_decode_text(link[8:]))
            return str(o.get("ps") or o.get("name") or "")[:50]
        except Exception:
            pass
    return ""


def _save_clean_configs_json(
    out_dir: Path,
    working: list[tuple[str, dict]],
    result: dict,
    out: "((str) -> None)",
    silent: bool = False,
) -> None:
    if not working:
        return
    try:
        clean_json = out_dir / "clean_configs.json"
        clean_txt = out_dir / "clean_links.txt"
        clean_b64 = out_dir / "clean_subscription_base64.txt"
        clean_json.write_text(
            json.dumps([cfg for _, cfg in working], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        result["clean_json_path"] = str(clean_json)
        links_from_json: list[str] = []
        for remark, full_cfg in working:
            ob = get_proxy_outbound_from_config(full_cfg)
            if ob:
                link = _outbound_to_link(ob, remark)
                if link:
                    links_from_json.append(link)
        if links_from_json:
            clean_txt.write_text("\n".join(links_from_json), encoding="utf-8")
            clean_b64.write_text(
                base64.standard_b64encode("\n".join(links_from_json).encode("utf-8")).decode("ascii"),
                encoding="utf-8",
            )
            result["clean_links_path"] = str(clean_txt)
            result["clean_b64_path"] = str(clean_b64)
        if not silent:
            out(f"\n  Clean configs saved ({len(working)} working only):")
            out(f"    - {clean_json}")
            if links_from_json:
                out(f"    - {clean_txt}")
                out(f"    - {clean_b64}")
    except OSError as e:
        if not silent:
            out(f"\n  [WARN] Could not save clean configs: {e}")


def _save_clean_configs_link(
    out_dir: Path,
    working: list[tuple[str, str]],
    result: dict,
    out: "((str) -> None)",
    silent: bool = False,
) -> None:
    if not working:
        return
    try:
        links_only = [link for _, link in working]
        clean_txt = out_dir / "clean_links.txt"
        clean_b64 = out_dir / "clean_subscription_base64.txt"
        clean_txt.write_text("\n".join(links_only), encoding="utf-8")
        clean_b64.write_text(
            base64.standard_b64encode("\n".join(links_only).encode("utf-8")).decode("ascii"),
            encoding="utf-8",
        )
        result["clean_links_path"] = str(clean_txt)
        result["clean_b64_path"] = str(clean_b64)
        if not silent:
            out(f"\n  Clean configs saved ({len(working)} working only):")
            out(f"    - {clean_txt}")
            out(f"    - {clean_b64}")
    except OSError as e:
        if not silent:
            out(f"\n  [WARN] Could not save clean configs: {e}")


def _make_port_pool() -> QueuePort[int]:
    q: QueuePort[int] = QueuePort()
    for i in range(PORT_POOL_SIZE):
        q.put(SOCKS_PORT_MIN + i)
    return q


def run_check(
    source: str,
    log: "None | ((str) -> None)" = None,
    cancel_check: "None | (() -> bool)" = None,
    progress_callback: "None | ((int, int) -> None)" = None,
    timeout: int = TEST_TIMEOUT,
    concurrent: int = 1,
    ping_limit: "int | None" = None,
) -> dict:
    """Run checker on a subscription URL, base64 string, single link, or JSON config list."""
    def out(msg: str) -> None:
        if log:
            log(msg)
        else:
            print(msg)

    result = {
        "working": [],
        "failed": [],
        "skipped": [],
        "clean_links_path": None,
        "clean_b64_path": None,
        "clean_json_path": None,
        "error": None,
        "cancelled": False,
    }

    out("=" * 60)
    out("  V2Ray/Xray Config Checker")
    out("=" * 60)

    xray_path = find_xray()
    if not xray_path:
        result["error"] = "Xray not found. Install from https://github.com/XTLS/Xray-core/releases"
        out("\n  [ERROR] Xray not found.")
        return result
    out(f"  Xray: {xray_path}\n")

    source = (source or "").strip()
    if not source:
        result["error"] = "No subscription or link entered."
        return result

    if source.startswith(("http://", "https://")):
        try:
            req = Request(source, headers={"User-Agent": "v2ray-checker/1.0"})
            with urlopen(req, timeout=20) as r:
                raw = r.read()
            source = raw.decode("utf-8", errors="replace")
        except URLError as e:
            result["error"] = f"Could not fetch URL: {e}"
            out(f"  [ERROR] Could not fetch subscription URL: {e}")
            return result

    json_configs = parse_json_subscription(source)
    if json_configs is not None:
        working_json: list[tuple[str, dict]] = []
        failed_json: list[tuple[str, str]] = []
        skipped_json: list[tuple[str, str]] = []
        seen_server_port: set[tuple[str, int]] = set()
        out_dir = Path(__file__).resolve().parent
        items_json: list[tuple[int, str, dict]] = []

        for idx, (remark, full_config) in enumerate(json_configs):
            ob = get_proxy_outbound_from_config(full_config)
            if ob:
                key = get_outbound_server_port(ob)
                if key and key in seen_server_port:
                    skipped_json.append((remark, "Duplicate (same server:port)"))
                    out(f"  [SKIP] Duplicate (same server:port)  |  {remark}")
                    continue
                if key:
                    seen_server_port.add(key)
            items_json.append((idx, remark, full_config))

        total_json = len(items_json)
        concurrency_json = max(1, min(concurrent, 16))
        limit_txt = f", ping <= {ping_limit} ms" if ping_limit is not None else ""
        out(f"  Detected JSON subscription: {len(json_configs)} config(s). Testing {total_json} (timeout {timeout}s, parallel: {concurrency_json}{limit_txt})...\n")

        port_pool = _make_port_pool()

        def _test_one_json(item: tuple[int, str, dict]) -> tuple[int, str, bool, str, float, dict]:
            idx, remark, full_config = item
            port = port_pool.get()
            try:
                fd, path = tempfile.mkstemp(suffix=".json")
                try:
                    test_config = build_test_config_from_json(full_config, port)
                    os.write(fd, json.dumps(test_config).encode("utf-8"))
                    os.close(fd)
                    fd = -1
                    ok, result_str, ping_ms = run_xray_and_test(path, port, timeout=timeout)
                    return (idx, remark, ok, result_str, ping_ms, full_config)
                finally:
                    if fd >= 0:
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
            except Exception as e:
                return (idx, remark, False, str(e), -1.0, full_config)
            finally:
                port_pool.put(port)

        completed = 0
        with ThreadPoolExecutor(max_workers=concurrency_json) as executor:
            futures = {executor.submit(_test_one_json, item): item for item in items_json}
            for future in as_completed(futures):
                if cancel_check and cancel_check():
                    result["cancelled"] = True
                    out("  [CANCELLED] Stopped by user.")
                    for f in futures:
                        f.cancel()
                    break
                try:
                    idx, remark, ok, result_str, ping_ms, full_config = future.result()
                except Exception as e:
                    item = futures[future]
                    remark, full_config = item[1], item[2]
                    ok, result_str, ping_ms = False, str(e), -1.0
                ping_val = int(ping_ms) if ping_ms >= 0 else -1
                over_limit = ping_limit is not None and ping_ms >= 0 and ping_ms > ping_limit
                if ok and not over_limit:
                    ob = get_proxy_outbound_from_config(full_config)
                    key = get_outbound_server_port(ob) if ob else None
                    host = key[0] if key else ""
                    new_remark = format_qwils_remark(host, ping_ms, remark)
                    working_json.append((new_remark, full_config))
                    out(f"  [OK]  result: {result_str}  |  ping: {ping_val} ms  |  {new_remark}")
                else:
                    fail_reason = f"ping > {ping_limit} ms" if over_limit else result_str
                    failed_json.append((remark, fail_reason))
                    out(f"  [FAIL]  result: {fail_reason}  |  ping: {ping_val}  |  {remark}")
                completed += 1
                if progress_callback:
                    progress_callback(completed, total_json)
                if completed % BATCH_SAVE_EVERY == 0 and working_json:
                    _save_clean_configs_json(out_dir, working_json, result, out, silent=True)

        if working_json:
            _save_clean_configs_json(out_dir, working_json, result, out, silent=False)
        result["working"] = [(r, "") for r, _ in working_json]
        result["failed"] = failed_json
        result["skipped"] = skipped_json
        return result

    links = decode_subscription(source)
    if not links:
        result["error"] = "No valid links found. Use subscription URL, base64, vmess/vless/trojan link, or JSON config array."
        out("  No valid links found in subscription.")
        return result

    working: list[tuple[str, str]] = []
    failed: list[tuple[str, str]] = []
    skipped: list[tuple[str, str]] = []
    seen_server_port: set[tuple[str, int]] = set()
    out_dir = Path(__file__).resolve().parent
    items_link: list[tuple[int, str, dict, str]] = []

    for i, link in enumerate(links):
        remark = get_remark(link) or f"Node-{i + 1}"
        outbound = parse_link(link)
        if not outbound:
            skipped.append((remark, "Unsupported link type (only vmess/vless/trojan)"))
            continue
        key = get_outbound_server_port(outbound)
        if key and key in seen_server_port:
            skipped.append((remark, "Duplicate (same server:port)"))
            out(f"  [SKIP] Duplicate (same server:port)  |  {remark}")
            continue
        if key:
            seen_server_port.add(key)
        items_link.append((i, remark, outbound, link))

    total_to_test = len(items_link)
    concurrency = max(1, min(concurrent, 16))
    limit_txt = f", ping <= {ping_limit} ms" if ping_limit is not None else ""
    out(f"  Found {len(links)} node(s). Testing {total_to_test} (timeout {timeout}s, parallel: {concurrency}{limit_txt})...\n")

    port_pool = _make_port_pool()

    def _test_one_link(item: tuple[int, str, dict, str]) -> tuple[int, str, dict, bool, str, float, str]:
        idx, remark, outbound, link = item
        port = port_pool.get()
        try:
            config = build_xray_config(outbound, port)
            fd, path = tempfile.mkstemp(suffix=".json")
            try:
                os.write(fd, json.dumps(config).encode("utf-8"))
                os.close(fd)
                fd = -1
                ok, result_str, ping_ms = run_xray_and_test(path, port, timeout=timeout)
                return (idx, remark, outbound, ok, result_str, ping_ms, link)
            finally:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                try:
                    os.unlink(path)
                except OSError:
                    pass
        except Exception as e:
            return (idx, remark, outbound, False, str(e), -1.0, link)
        finally:
            port_pool.put(port)

    completed = 0
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = {executor.submit(_test_one_link, item): item for item in items_link}
        for future in as_completed(futures):
            if cancel_check and cancel_check():
                result["cancelled"] = True
                out("  [CANCELLED] Stopped by user.")
                for f in futures:
                    f.cancel()
                break
            try:
                idx, remark, outbound, ok, result_str, ping_ms, link = future.result()
            except Exception as e:
                item = futures[future]
                remark, outbound, link = item[1], item[2], item[3]
                ok, result_str, ping_ms = False, str(e), -1.0

            ping_val = int(ping_ms) if ping_ms >= 0 else -1
            over_limit = ping_limit is not None and ping_ms >= 0 and ping_ms > ping_limit
            if ok and not over_limit:
                key = get_outbound_server_port(outbound)
                host = key[0] if key else ""
                new_remark = format_qwils_remark(host, ping_ms, remark)
                new_link = apply_remark_to_link(link, new_remark)
                working.append((new_remark, new_link))
                out(f"  [OK]  result: {result_str}  |  ping: {ping_val} ms  |  {new_remark}")
            else:
                fail_reason = f"ping > {ping_limit} ms" if over_limit else result_str
                failed.append((remark, fail_reason))
                out(f"  [FAIL]  result: {fail_reason}  |  ping: {ping_val}  |  {remark}")

            completed += 1
            if progress_callback:
                progress_callback(completed, total_to_test)
            if completed % BATCH_SAVE_EVERY == 0 and working:
                _save_clean_configs_link(out_dir, working, result, out, silent=True)

    out("")
    out("=" * 60)
    out(f"  Working: {len(working)}  |  Failed: {len(failed)}  |  Skipped: {len(skipped)}")
    if result["cancelled"]:
        out("  (Stopped by user.)")
    out("=" * 60)

    if working:
        _save_clean_configs_link(out_dir, working, result, out, silent=False)

    result["working"] = working
    result["failed"] = failed
    result["skipped"] = skipped
    return result


def main() -> None:
    if len(sys.argv) < 2:
        print("  Usage:")
        print("    python v2ray_checker.py <subscription_url>")
        print("    python v2ray_checker.py <base64_subscription_string>")
        print("    python v2ray_checker.py vmess://... | vless://... | trojan://...")
        sys.exit(0)
    run_check(sys.argv[1])


if __name__ == "__main__":
    main()
