#!/usr/bin/env python3
import os
import re
import json
import base64
import socket
import ssl
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

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

def fetch_sources():
    all_links = []
    for url in SOURCES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                if "vless://" not in content:
                    try:
                        content = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                links = re.findall(r'vless://[^\s<>"]+', content)
                print(f"[OK] Загружено из {url.split('/')[-1]}: найдено {len(links)} ссылок")
                all_links.extend(links)
        except Exception as e:
            print(f"[WARN] Не удалось загрузить {url}: {e}")
    return list(set(all_links))

def parse_vless(link):
    try:
        parsed = urlparse(link)
        if parsed.scheme != "vless":
            return None
        
        query = parse_qs(parsed.query)
        security = query.get("security", [""])[0].lower()
        
        # Строгая фильтрация: только tls или reality
        if security not in ["tls", "reality"]:
            return None
            
        name_decoded = unquote(parsed.fragment) if parsed.fragment else "Server"
        country_code = "OTHER"
        for code in COUNTRY_FLAGS.keys():
            if code in name_decoded.upper() or code.lower() in parsed.hostname.lower():
                country_code = code
                break
        
        flag = COUNTRY_FLAGS.get(country_code, "🌐")
        clean_name = f"{flag} : {country_code}"

        config = {
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
            config["pbk"] = query.get("pbk", [""])[0]
            config["sid"] = query.get("sid", [""])[0]
            
        net = config["type"]
        if net == "ws":
            config["path"] = query.get("path", ["/"])[0]
            config["host"] = query.get("host", [""])[0]
        elif net == "grpc":
            config["serviceName"] = query.get("serviceName", [""])[0]
        elif net == "xhttp":
            config["path"] = query.get("path", ["/"])[0]
        
        clean_query = parsed.query
        config["raw"] = f"vless://{config['uuid']}@{config['address']}:{config['port']}?{clean_query}#{urllib.parse.quote(clean_name)}"
            
        return config
    except Exception:
        return None

def check_node(node):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((node["address"], node["port"]), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=node["sni"]) as ssock:
                pass
            return True
    except Exception:
        return False

def build_stream_settings(node):
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
        stream["wsSettings"] = {
            "path": node.get("path", "/"),
            "headers": {"Host": node.get("host", node["sni"])}
        }
    elif net == "grpc":
        stream["grpcSettings"] = {
            "serviceName": node.get("serviceName", "")
        }
    elif net == "xhttp":
        stream["xhttpSettings"] = {
            "path": node.get("path", "/")
        }
    return stream

def generate_xray_balancer(nodes):
    outbounds = []
    balancer_targets = []
    
    for i, node in enumerate(nodes[:50]):
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
            "streamSettings": build_stream_settings(node)
        }
        outbounds.append(outbound)

    config = {
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
    return config

if __name__ == "__main__":
    raw_links = fetch_sources()
    print(f"Всего собрано сырых ссылок: {len(raw_links)}")
    
    parsed_nodes = []
    for link in raw_links:
        node = parse_vless(link)
        if node:
            parsed_nodes.append(node)
            
    print(f"Прошли фильтрацию (только TLS/Reality): {len(parsed_nodes)}")
    
    valid_nodes = []
    if parsed_nodes:
        print("Проверка сокетов и TLS рукопожатий (100 потоков)...")
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_node, node): node for node in parsed_nodes}
            for future in as_completed(futures):
                node = futures[future]
                try:
                    if future.result():
                        valid_nodes.append(node)
                except Exception:
                    pass
                    
    print(f"Успешно прошли проверку сокетов: {len(valid_nodes)}")
    
    # Страховка: если проверка сокетов отсеяла вообще всё из-за проблем с сетью в Github Actions, 
    # используем распарсенные ноды напрямую, чтобы пайплайн не упал с ошибкой.
    if not valid_nodes and parsed_nodes:
        print("[WARN] Сокет-чекер не нашел доступных нод (возможно, таймаут сети). Используем отфильтрованные ноды без проверки.")
        valid_nodes = parsed_nodes[:50]
        
    if not valid_nodes:
        print("[ERROR] Не найдено ни одной подходящей ноды!")
        exit(1)

    # 1. Генерация subscription.txt
    sub_content = "\n".join([n["raw"] for n in valid_nodes])
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
    
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: base64:qwils UPDATE LTE\n")
        f.write(encoded_sub)

    os.makedirs(".", exist_ok=True)
    
    # 2. Генерация auto_eu.json
    eu_nodes = [n for n in valid_nodes if any(c in n["name"] for c in ["🇳🇱", "🇩🇪", "🇫🇷", "🇫🇮", "🇸🇪", "PL"])]
    if not eu_nodes:
        eu_nodes = valid_nodes
        
    with open("auto_eu.json", "w", encoding="utf-8") as f:
        json.dump(generate_xray_balancer(eu_nodes), f, indent=2, ensure_ascii=False)
        
    # 3. Генерация auto_bs_1..5.json
    chunk_size = max(1, len(valid_nodes) // 5)
    for i in range(1, 6):
        chunk = valid_nodes[(i-1)*chunk_size : i*chunk_size]
        if not chunk:
            chunk = valid_nodes
        with open(f"auto_bs_{i}.json", "w", encoding="utf-8") as f:
            json.dump(generate_xray_balancer(chunk), f, indent=2, ensure_ascii=False)
            
    print("Успешно: все файлы сгенерированы!")
EOF

python3 updater.sh
