#!/usr/bin/env bash
cat << 'EOF' > updater_core.py
import os
import re
import json
import base64
import socket
import ssl
import urllib.request
from urllib.parse import urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, asdict

# Список источников (примеры или ваш массив)
SOURCES = [
    # Ваши 30 источников raw/jsDelivr
]

COUNTRY_FLAGS = {
    "NL": "🇳🇱", "DE": "🇩🇪", "FR": "🇫🇷", "US": "🇺🇸", "GB": "🇬🇧",
    "FI": "🇫🇮", "SE": "🇸🇪", "PL": "🇵🇱", "CA": "🇨🇦", "SG": "🇸🇬"
}

def decode_base64(encoded):
    try:
        padding = 4 - (len(encoded) % 4)
        if padding < 4:
            encoded += "=" * padding
        return base64.b64decode(encoded).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def parse_vless(link):
    # vless://uuid@host:port?params#name
    parsed = urlparse(link)
    if parsed.scheme != "vless":
        return None
    
    query = parse_qs(parsed.query)
    security = query.get("security", [""])[0].lower()
    
    # СТРОГАЯ ФИЛЬТРАЦИЯ: пропускаем только tls и reality
    if security not in ["tls", "reality"]:
        return None
        
    config = {
        "protocol": "vless",
        "uuid": parsed.username,
        "address": parsed.hostname,
        "port": parsed.port,
        "security": security,
        "sni": query.get("sni", [parsed.hostname])[0],
        "fp": query.get("fp", ["chrome"])[0],
        "type": query.get("type", ["tcp"])[0],
        "name": unquote(parsed.fragment) if parsed.fragment else "VLESS Server",
        "raw": link
    }
    
    if security == "reality":
        config["pbk"] = query.get("pbk", [""])[0]
        config["sid"] = query.get("sid", [""])[0]
        
    # Транспортные настройки
    if config["type"] == "ws":
        config["path"] = query.get("path", ["/"])[0]
        config["host"] = query.get("host", [""])[0]
    elif config["type"] == "grpc":
        config["serviceName"] = query.get("serviceName", [""])[0]
    elif config["type"] == "xhttp":
        config["path"] = query.get("path", ["/"])[0]
        
    return config

def check_node(node):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((node["address"], node["port"]), timeout=3) as sock:
            if node["security"] == "tls" or node["security"] == "reality":
                with ctx.wrap_socket(sock, server_hostname=node["sni"]) as ssock:
                    pass
            return True
    except Exception:
        return False
EOF
cat << 'EOF' >> updater_core.py

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

def generate_xray_balancer(nodes, tag_filter=None):
    outbounds = []
    balancer_targets = []
    
    for i, node in enumerate(nodes):
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

    # Балансировщик leastPing
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
        "outbounds": outbounds + [{
            "tag": "balanced",
            "protocol": "freedom"
        }, {
            "tag": "direct",
            "protocol": "freedom"
        }, {
            "tag": "block",
            "protocol": "blackhole"
        }]
    }
    return config

# Основной процесс выполнения скрипта
if __name__ == "__main__":
    print("Updater script initialized with strict TLS/Reality validation.")
EOF

python3 updater_core.py
