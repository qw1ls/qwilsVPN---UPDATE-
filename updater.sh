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

# Ваши источники + 25 сгенерированных ссылок от hiztin
SOURCES = [
    "https://fastly.jsdelivr.net/gh/whoahaow/rjsxrd@main/githubmirror/bypass/bypass-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/refs/heads/main/all/configs.txt",
]

# Автоматически добавляем 25 файлов от hiztin (от 1.txt до 25.txt)
for i in range(1, 26):
    SOURCES.append(f"https://raw.githubusercontent.com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/{i}.txt")

# Расширенный словарь флагов стран
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
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
                # Если контент закодирован в base64 (часто бывает в подписках)
                if "vless://" not in content:
                    try:
                        decoded_bytes = base64.b64decode(content.strip())
                        content = decoded_bytes.decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                links = re.findall(r'vless://[^\s<>"]+', content)
                all_links.extend(links)
        except Exception as e:
            print(f"Пропуск источника (ошибка загрузки): {url} -> {e}")
    return list(set(all_links))

def parse_vless(link):
    try:
        parsed = urlparse(link)
        if parsed.scheme != "vless":
            return None
        
        query = parse_qs(parsed.query)
        security = query.get("security", [""])[0].lower()
        
        # СТРОГАЯ ФИЛЬТРАЦИЯ: пропускаем ТОЛЬКО tls и reality (отбрасываем none/без шифрования)
        if security not in ["tls", "reality"]:
            return None
            
        # Определяем страну и флаг для имени ноды
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
            "raw": "" # Сформируем заново с чистым именем
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
        
        # Пересобираем чистую ссылку с форматом имени «ФЛАГ : Страна»
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
        
        with socket.create_connection((node["address"], node["port"]), timeout=2.5) as sock:
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
    
    for i, node in enumerate(nodes[:50]): # Ограничиваем топ-50 для стабильности балансировщика
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
    print(f"Всего источников для опроса: {len(SOURCES)}")
    raw_links = fetch_sources()
    print(f"Найдено сырых ссылок: {len(raw_links)}")
    
    parsed_nodes = []
    for link in raw_links:
        node = parse_vless(link)
        if node:
            parsed_nodes.append(node)
            
    print(f"Прошли фильтрацию (только TLS/Reality): {len(parsed_nodes)}")
    
    print("Проверка сокетов и TLS рукопожатий (100 потоков)...")
    valid_nodes = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(check_node, node): node for node in parsed_nodes}
        for future in as_completed(futures):
            node = futures[future]
            if future.result():
                valid_nodes.append(node)
                
    print(f"Успешно прошли проверку: {len(valid_nodes)}")
    
    # 1. Генерация subscription.txt
    sub_content = "\n".join([n["raw"] for n in valid_nodes])
    encoded_sub = base64.b64encode(sub_content.encode('utf-8')).decode('utf-8')
    
    with open("subscription.txt", "w", encoding="utf-8") as f:
        f.write("#profile-title: base64:qwils UPDATE LTE\n")
        f.write(encoded_sub)

    os.makedirs(".", exist_ok=True)
    
    # 2. Генерация auto_eu.json (Европа или любые доступные)
    eu_nodes = [n for n in valid_nodes if any(c in n["name"] for c in ["🇳🇱", "🇩🇪", "🇫🇷", "🇫🇮", "🇸🇪", "PL"])]
    if not eu_nodes:
        eu_nodes = valid_nodes
        
    with open("auto_eu.json", "w", encoding="utf-8") as f:
        json.dump(generate_xray_balancer(eu_nodes), f, indent=2, ensure_ascii=False)
        
    # 3. Генерация auto_bs_1..5.json (Белые списки РФ / чанки)
    chunk_size = max(1, len(valid_nodes) // 5)
    for i in range(1, 6):
        chunk = valid_nodes[(i-1)*chunk_size : i*chunk_size]
        if not chunk:
            chunk = valid_nodes
        with open(f"auto_bs_{i}.json", "w", encoding="utf-8") as f:
            json.dump(generate_xray_balancer(chunk), f, indent=2, ensure_ascii=False)
            
    print("Генерация файлов завершена успешно!")
EOF

python3 updater.sh
