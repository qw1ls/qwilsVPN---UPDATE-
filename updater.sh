#!/usr/bin/env python3
import os
import re
import json
import base64
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote

# Список источников
SOURCES = [
    "https://fastly.jsdelivr.net/gh/whoahaow/rjsxrd@main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/refs/heads/main/all/configs.txt",
]

# Добавляем 25 ссылок от hiztin
for i in range(1, 26):
    SOURCES.append(f"https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/{i}.txt")

COUNTRY_FLAGS = {
    "NL": "🇳🇱", "DE": "🇩🇪", "FR": "🇫🇷", "US": "🇺🇸", "GB": "🇬🇧",
    "FI": "🇫🇮", "SE": "🇸🇪", "PL": "🇵🇱", "CA": "🇨🇦", "SG": "🇸🇬",
    "TR": "🇹🇷", "JP": "🇯🇵", "KR": "🇰🇷", "IT": "🇮🇹", "ES": "🇪🇸",
    "CH": "🇨🇭", "AT": "🇦🇹", "NO": "🇳🇴", "DK": "🇩🇰", "IE": "🇮🇪",
    "RO": "🇷🇴", "UA": "🇺🇦", "CZ": "🇨🇿", "AE": "🇦🇪", "BG": "🇧🇬",
    "KZ": "🇰🇿", "GE": "🇬🇪", "AM": "🇦🇲", "MD": "🇲🇩", "OTHER": "🌐"
}

def main():
    print("Запуск сбора конфигураций...")
    all_links = []
    
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                if "vless://" not in content:
                    try:
                        content = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                links = re.findall(r'vless://[^\s<>"]+', content)
                print(f"[OK] {url.split('/')[-1]} -> найдено: {len(links)}")
                all_links.extend(links)
        except Exception as e:
            print(f"[WARN] Ошибка загрузки {url}: {e}")

    unique_links = list(set(all_links))
    print(f"Всего уникальных ссылок собрано: {len(unique_links)}")

    valid_nodes = []
    for link in unique_links:
        try:
            parsed = urlparse(link)
            if parsed.scheme != "vless":
                continue
            
            query = parse_qs(parsed.query)
            security = query.get("security", [""])[0].lower()
            
            # Строгая фильтрация: только tls или reality
            if security not in ["tls", "reality"]:
                continue
                
            name_decoded = unquote(parsed.fragment) if parsed.fragment else "Server"
            country_code = "OTHER"
            for code in COUNTRY_FLAGS.keys():
                if code in name_decoded.upper() or code.lower() in parsed.hostname.lower():
                    country_code = code
                    break
            
            flag = COUNTRY_FLAGS.get(country_code, "🌐")
            clean_name = f"{flag} : {country_code}"

            node = {
                "protocol": "vless",
                "uuid": parsed.username,
                "address": parsed.hostname,
                "port": parsed.port,
                "security": security,
                "sni": query.get("sni", [parsed.hostname])[0],
                "fp": query.get("fp", ["chrome"])[0],
                "type": query.get("type", ["tcp"])[0],
                "name": clean_name,
            }
            
            if security == "reality":
                node["pbk"] = query.get("pbk", [""])[0]
                node["sid"] = query.get("sid", [""])[0]
                
            net = node["type"]
            if net == "ws":
                node["path"] = query.get("path", ["/"])[0]
                node["host"] = query.get("host", [""])[0]
            elif net == "grpc":
                node["serviceName"] = query.get("serviceName", [""])[0]
            elif net == "xhttp":
                node["path"] = query.get("path", ["/"])[0]
            
            clean_query = parsed.query
            node["raw"] = f"vless://{node['uuid']}@{node['address']}:{node['port']}?{clean_query}#{urllib.parse.quote(clean_name)}"
            
            valid_nodes.append(node)
        except Exception:
            continue

    print(f"Прошло фильтрацию TLS/Reality: {len(valid_nodes)}")

    # Защита от пустого списка, чтобы скрипт никогда не падал
    if not valid_nodes:
        print("[WARN] Ноды не найдены, используем дефолтную заглушку.")
        valid_nodes = [{
            "protocol": "vless", "uuid": "00000000-0000-0000-0000-000000000000",
            "address": "127.0.0.1", "port": 443, "security": "tls", "sni": "example.com",
            "type": "tcp", "name": "🌐 : OTHER", "raw": "vless://00000000-0000-0000-0000-000000000000@127.0.0.1:443?security=tls#%F0%9F%8C%90%20%3A%20OTHER"
        }]

    # 1. Генерация subscription.txt
    sub_content = "\n".join([n["raw"] for n in valid_nodes])
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
    
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: base64:qwils UPDATE LTE\n")
        f.write(encoded_sub)

    os.makedirs(".", exist_ok=True)

    # Функция формирования streamSettings для Xray
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

    def make_balancer(nodes_chunk):
        outbounds = []
        balancer_targets = []
        for i, node in enumerate(nodes_chunk[:50]):
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

        return {
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

    # 2. Генерация auto_eu.json
    eu_nodes = [n for n in valid_nodes if any(c in n["name"] for c in ["🇳🇱", "🇩🇪", "🇫🇷", "🇫🇮", "🇸🇪", "PL"])]
    if not eu_nodes:
        eu_nodes = valid_nodes
        
    with open("auto_eu.json", "w", encoding="utf-8") as f:
        json.dump(make_balancer(eu_nodes), f, indent=2, ensure_ascii=False)
        
    # 3. Генерация auto_bs_1..5.json
    chunk_size = max(1, len(valid_nodes) // 5)
    for i in range(1, 6):
        chunk = valid_nodes[(i-1)*chunk_size : i*chunk_size]
        if not chunk:
            chunk = valid_nodes
        with open(f"auto_bs_{i}.json", "w", encoding="utf-8") as f:
            json.dump(make_balancer(chunk), f, indent=2, ensure_ascii=False)

    print("Все файлы успешно созданы. Завершение без ошибок.")

if __name__ == "__main__":
    main()
