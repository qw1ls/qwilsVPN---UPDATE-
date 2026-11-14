#!/usr/bin/env python3
import os
import re
import json
import base64
import socket
import ssl
import time
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

SOURCES = [
    "https://fastly.jsdelivr.net/gh/whoahaow/rjsxrd@main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/refs/heads/main/all/configs.txt",
    "https://raw.githubusercontent.com/wlunlocker/vpn-configs/refs/heads/main/blacklist_all.txt",
    "https://raw.githubusercontent.com/wlunlocker/vpn-configs/refs/heads/main/whitelist_all.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/refs/heads/main/Sub1.txt",
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/v2ray-base64.txt",
]

for i in range(1, 26):
    SOURCES.append(f"https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/{i}.txt")

COUNTRY_NAMES = {
    "NL": ("🇳🇱", "Нидерланды"),
    "DE": ("🇩🇪", "Германия"),
    "FR": ("🇫🇷", "Франция"),
    "US": ("🇺🇸", "США"),
    "GB": ("🇬🇧", "Великобритания"),
    "FI": ("🇫🇮", "Финляндия"),
    "SE": ("🇸🇪", "Швеция"),
    "PL": ("🇵🇱", "Польша"),
    "CA": ("🇨🇦", "Канада"),
    "SG": ("🇸🇬", "Сингапур"),
    "TR": ("🇹🇷", "Турция"),
    "JP": ("🇯🇵", "Япония"),
    "KR": ("🇰🇷", "Южная Корея"),
    "IT": ("🇮🇹", "Италия"),
    "ES": ("🇪🇸", "Испания"),
    "CH": ("🇨🇭", "Швейцария"),
    "AT": ("🇦🇹", "Австрия"),
    "NO": ("🇳🇴", "Норвегия"),
    "DK": ("🇩🇰", "Дания"),
    "IE": ("🇮🇪", "Ирландия"),
    "RO": ("🇷🇴", "Румыния"),
    "UA": ("🇺🇦", "Украина"),
    "CZ": ("🇨🇿", "Чехия"),
    "AE": ("🇦🇪", "ОАЭ"),
    "BG": ("🇧🇬", "Болгария"),
    "KZ": ("🇰🇿", "Казахстан"),
    "GE": ("🇬🇪", "Грузия"),
    "AM": ("🇦🇲", "Армения"),
    "MD": ("🇲🇩", "Молдова"),
}

def fetch_sources():
    all_links = []
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                if "vless://" not in content:
                    try:
                        content = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                links = re.findall(r'vless://[^\s<>"]+', content)
                all_links.extend(links)
        except Exception:
            pass
    return list(set(all_links))

# Проверка на реальную скорость: отсекает всё, что дольше 0.12 сек (120 мс) или нестабильно
def check_node_speed_and_stability(node):
    latencies = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        for _ in range(4): # 4 быстрых, но точных прохода
            start_time = time.time()
            with socket.create_connection((node["address"], node["port"]), timeout=3.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=node["sni"]) as ssock:
                    request_data = f"GET / HTTP/1.1\r\nHost: {node['sni']}\r\nConnection: close\r\n\r\n".encode('utf-8')
                    ssock.sendall(request_data)
                    ssock.recv(32)
            latencies.append(time.time() - start_time)
            
        avg_latency = sum(latencies) / len(latencies)
        
        # ЖЕСТКИЙ ФИЛЬТР: Если средний реальный пинг выше 120мс или большой разброс — брак
        if avg_latency > 0.12 or (max(latencies) - min(latencies) > 0.6):
            return False, 0.0
            
        return True, avg_latency
    except Exception:
        return False, 0.0

def main():
    print("Загрузка ссылок из всех источников...")
    raw_links = fetch_sources()
    print(f"Собрано сырых ссылок: {len(raw_links)}")
    
    parsed_nodes = []
    seen_endpoints = set()
    
    for link in raw_links:
        try:
            if "%23" in link:
                link = link.split("%23")[0]
            if "#" in link:
                link = link.split("#")[0]

            parsed = urlparse(link)
            if parsed.scheme != "vless":
                continue
            
            query = parse_qs(parsed.query)
            security = query.get("security", [""])[0].lower()
            
            if security not in ["tls", "reality"]:
                continue
                
            endpoint = f"{parsed.hostname}:{parsed.port}"
            if endpoint in seen_endpoints:
                continue
            seen_endpoints.add(endpoint)
                
            net_type = query.get("type", ["tcp"])[0].lower()
            if net_type not in ["tcp", "ws", "grpc", "xhttp"]:
                net_type = "tcp"

            name_decoded = unquote(parsed.fragment) if parsed.fragment else ""
            full_text = f"{name_decoded} {parsed.path} {parsed.hostname}".upper()
            
            country_code = "OTHER"
            for code in COUNTRY_NAMES.keys():
                if re.search(rf"(^|[^A-Z]){code}([^A-Z]|$)", full_text):
                    country_code = code
                    break
            
            if country_code in COUNTRY_NAMES:
                flag, c_name = COUNTRY_NAMES[country_code]
            else:
                flag, c_name = "🌐", "Другие"
            
            clean_name = f"{flag} {c_name}"

            node = {
                "protocol": "vless",
                "uuid": parsed.username,
                "address": parsed.hostname,
                "port": parsed.port,
                "security": security,
                "sni": query.get("sni", [parsed.hostname])[0],
                "fp": query.get("fp", ["chrome"])[0],
                "type": net_type,
                "name": clean_name,
            }
            
            if security == "reality":
                node["pbk"] = query.get("pbk", [""])[0]
                node["sid"] = query.get("sid", [""])[0]
                
            if net_type == "ws":
                node["path"] = query.get("path", ["/"])[0]
                node["host"] = query.get("host", [""])[0]
            elif net_type == "grpc":
                node["serviceName"] = query.get("serviceName", [""])[0]
            elif net_type == "xhttp":
                node["path"] = query.get("path", ["/"])[0]
            
            clean_query = f"security={security}&type={net_type}&sni={node['sni']}&fp={node['fp']}"
            if security == "reality":
                clean_query += f"&pbk={node.get('pbk','')}&sid={node.get('sid','')}"
            
            node["raw"] = f"vless://{node['uuid']}@{node['address']}:{node['port']}?{clean_query}#{urllib.parse.quote(clean_name)}"
            
            parsed_nodes.append(node)
        except Exception:
            continue

    print(f"Уникальных нод для проверки по скорости: {len(parsed_nodes)}")
    print("🔥 Запуск скоростного стресс-теста с отсевом медленных серверов (>120мс)...")
    
    valid_nodes = []
    with ThreadPoolExecutor(max_workers=35) as executor:
        futures = {executor.submit(check_node_speed_and_stability, node): node for node in parsed_nodes}
        for future in as_completed(futures):
            node = futures[future]
            try:
                is_alive, latency = future.result()
                if is_alive:
                    node['latency'] = latency
                    valid_nodes.append(node)
            except Exception:
                pass

    # Сортируем строго по реальному быстродействию (самые быстрые сверху)
    valid_nodes.sort(key=lambda x: x.get('latency', 999))
    print(f"💎 Отобрано ЭЛИТНЫХ и быстрых нод (пинг < 120мс): {len(valid_nodes)}")

    if not valid_nodes:
        valid_nodes = [{
            "protocol": "vless", "uuid": "00000000-0000-0000-0000-000000000000",
            "address": "127.0.0.1", "port": 443, "security": "tls", "sni": "example.com",
            "type": "tcp", "name": "🌐 Другие", "latency": 0.1,
            "raw": "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443?security=tls#%F0%9F%8C%90%20%D0%94%D1%80%D1%83%D0%B3%D0%B8%D0%B5"
        }]

    sub_content = "\n".join([n["raw"] for n in valid_nodes])
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
    
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: base64:qwils UPDATE LTE\n")
        f.write(encoded_sub)

    os.makedirs(".", exist_ok=True)

    def build_stream(node):
        stream = {
            "network": node.get("type", "tcp"),
            "security": node["security"]
        }
        if node["security"] == "tls":
            stream["tlsSettings"] = {
                "serverName": node["sni"],
                "allowInsecure": False,
                "fingerprint": node.get("fp", "chrome")
            }
        elif node["security"] == "reality":
            stream["realitySettings"] = {
                "serverName": node["sni"],
                "fingerprint": node.get("fp", "chrome"),
                "publicKey": node.get("pbk", ""),
                "shortId": node.get("sid", "")
            }
        net = node.get("type", "tcp")
        if net == "ws":
            stream["wsSettings"] = {"path": node.get("path", "/"), "headers": {"Host": node.get("host", node["sni"])}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": node.get("serviceName", "")}
        elif net == "xhttp":
            stream["xhttpSettings"] = {"path": node.get("path", "/")}
        return stream

    def make_balancer(nodes_chunk, balancer_name):
        outbounds = []
        balancer_targets = []
        # Берем топ-25 самых быстрых серверов для идеального JSON
        for i, node in enumerate(nodes_chunk[:25]):
            tag = f"proxy_{i}"
            balancer_targets.append(tag)
            outbound = {
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": node["address"],
                        "port": node["port"],
                        "users": [{"id": node["uuid"], "encryption": "none", "flow": ""}]
                    }]
                },
                "streamSettings": build_stream(node)
            }
            outbounds.append(outbound)

        if not balancer_targets:
            balancer_targets = ["fallback_proxy"]
            outbounds.append({
                "tag": "fallback_proxy",
                "protocol": "vless",
                "settings": {"vnext": [{
                    "address": "127.0.0.1", "port": 443, 
                    "users": [{"id": "00000000-0000-0000-0000-000000000000", "encryption": "none"}]
                }]},
                "streamSettings": {"network": "tcp", "security": "tls"}
            })

        return {
            "tag_name": balancer_name,
            "log": {"loglevel": "warning"},
            "routing": {
                "balancer": [{
                    "tag": "balancer",
                    "selector": balancer_targets,
                    "strategy": {"type": "leastPing"}
                }],
                "rules": [{
                    "type": "field",
                    "balancerTag": "balancer",
                    "outboundTag": "balanced"
                }]
            },
            "outbounds": outbounds + [
                {"tag": "balanced", "protocol": "freedom"},
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"}
            ]
        }

    eu_nodes = [n for n in valid_nodes if any(c in n["name"] for c in ["Германия", "Нидерланды", "Франция", "Финляндия", "Швеция", "Польша"])]
    if not eu_nodes:
        eu_nodes = valid_nodes
        
    balancer_eu = make_balancer(eu_nodes, "🇪🇺 Авто")
    with open("auto_eu.json", "w", encoding="utf-8") as f:
        json.dump(balancer_eu, f, indent=2, ensure_ascii=False)
        
    chunk_size = max(1, len(valid_nodes) // 5)
    for i in range(1, 6):
        chunk = valid_nodes[(i-1)*chunk_size : i*chunk_size]
        if not chunk:
            chunk = valid_nodes
            
        balancer_bs = make_balancer(chunk, f"🇷🇺 Авто БС - {i}")
        with open(f"auto_bs_{i}.json", "w", encoding="utf-8") as f:
            json.dump(balancer_bs, f, indent=2, ensure_ascii=False)

    print("Готово! Все файлы обновлены строго по критерию быстрого пинга.")

if __name__ == "__main__":
    main()
