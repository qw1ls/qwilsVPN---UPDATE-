#!/bin/bash

python3 - << 'EOF'
import urllib.request
import urllib.parse
import socket
import ssl
import re
import json
import base64
import concurrent.futures

raw_urls = [
    "https:// raw . githubusercontent . com / 0xRadikal / Free-v2ray-Configs / refs / heads / main / all / configs . txt",
    "https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_SS%2BAll_RUS . txt",
    "https:// fastly . jsdelivr . net / gh / whoahaow / rjsxrd@main / githubmirror / bypass / bypass-all . txt",
    "https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_VLESS_RUS . txt",
    "https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / Vless-Reality-White-Lists-Rus-Mobile . txt"
]

for i in range(1, 26):
    raw_urls.append(f"https:// raw . githubusercontent . com / hiztin / VLESS-PO-GRIBI / main / deploy / subscriptions / {i} . txt")

urls = [u.replace(" ", "") for u in raw_urls]

def fetch_url(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

print("=== 1. Скачивание всех 30 источников ===")
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    texts = list(executor.map(fetch_url, urls))

raw_data = "\n".join(texts)
raw_links = set(re.findall(r'(?:vless|ss|trojan)://[^\s"\'<>]+', raw_data))
print(f"Найдено уникальных строк: {len(raw_links)}")

unique_endpoints = {}
for link in raw_links:
    base_link = link.split('#')[0]
    base_link = re.sub(r'%23.*', '', base_link)
    m = re.search(r'@([^:/?#]+):(\d+)', base_link)
    if m:
        host, port = m.group(1), int(m.group(2))
        if host not in ('127.0.0.1', '0.0.0.0', 'localhost') and 1 <= port <= 65535:
            proto = base_link.split('://')[0]
            key = f"{proto}://{host}:{port}"
            if key not in unique_endpoints:
                unique_endpoints[key] = (link, base_link, host, port)

print(f"После удаления дублей узлов осталось для проверки: {len(unique_endpoints)}")

def check_server(item):
    orig_link, base_link, host, port = item
    try:
        with socket.create_connection((host, port), timeout=2.5) as sock:
            if 'security=tls' in base_link or 'security=reality' in base_link or base_link.startswith('trojan://'):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    pass
        return (orig_link, base_link, host, port)
    except Exception:
        return None

print("=== 2. Запуск глубокой TCP/TLS проверки в 100 потоков ===")
alive_servers = []
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
    for res in executor.map(check_server, unique_endpoints.values()):
        if res is not None:
            alive_servers.append(res)

print(f"Проверка завершена! Выжило рабочих серверов: {len(alive_servers)}")

countries = [
    (r'(netherlands|holland|\bNL\b)', '🇳🇱', 'Нидерланды'),
    (r'(united states|america|\bUS\b|\bUSA\b)', '🇺🇸', 'США'),
    (r'(germany|nuremberg|frankfurt|\bDE\b)', '🇩🇪', 'Германия'),
    (r'(finland|helsinki|\bFI\b)', '🇫🇮', 'Финляндия'),
    (r'(france|roubaix|paris|\bFR\b)', '🇫🇷', 'Франция'),
    (r'(sweden|stockholm|\bSE\b)', '🇸🇪', 'Швеция'),
    (r'(poland|warsaw|wroclaw|\bPL\b)', '🇵🇱', 'Польша'),
    (r'(kazakhstan|almaty|\bKZ\b)', '🇰🇿', 'Казахстан'),
    (r'(japan|tokyo|inzai|\bJP\b)', '🇯🇵', 'Япония'),
    (r'(korea|seoul|\bKR\b)', '🇰🇷', 'Южная Корея'),
    (r'(singapore|\bSG\b)', '🇸🇬', 'Сингапур'),
    (r'(turkey|istanbul|sultanbeyli|\bTR\b)', '🇹🇷', 'Турция'),
    (r'(hong kong|\bHK\b)', '🇭🇰', 'Гонконг'),
    (r'(united arab|emirates|dubai|\bAE\b)', '🇦🇪', 'ОАЭ'),
    (r'(united kingdom|london|manchester|\bUK\b|\bGB\b)', '🇬🇧', 'Великобритания'),
    (r'(latvia|riga|\bLV\b)', '🇱🇻', 'Латвия'),
    (r'(estonia|tallinn|\bEE\b)', '🇪🇪', 'Эстония'),
    (r'(lithuania|vilnius|\bLT\b)', '🇱🇹', 'Литва'),
    (r'(austria|vienna|\bAT\b)', '🇦🇹', 'Австрия'),
    (r'(switzerland|zurich|\bCH\b)', '🇨🇭', 'Швейцария'),
    (r'(canada|montreal|toronto|\bCA\b)', '🇨🇦', 'Канада'),
    (r'(spain|madrid|\bES\b)', '🇪🇸', 'Испания'),
    (r'(italy|milan|\bIT\b)', '🇮🇹', 'Италия'),
    (r'(ukraine|kyiv|\bUA\b)', '🇺🇦', 'Украина'),
    (r'(belarus|minsk|\bBY\b)', '🇧🇾', 'Беларусь'),
    (r'(czechia|czech|prague|\bCZ\b)', '🇨🇿', 'Чехия'),
    (r'(india|delhi|mumbai|\bIN\b)', '🇮🇳', 'Индия'),
    (r'(australia|sydney|\bAU\b)', '🇦🇺', 'Австралия'),
    (r'(brazil|sao paulo|\bBR\b)', '🇧🇷', 'Бразилия'),
    (r'(bulgaria|sofia|\bBG\b)', '🇧🇬', 'Болгария'),
    (r'(romania|bucharest|\bRO\b)', '🇷🇴', 'Румыния'),
    (r'(ireland|dublin|\bIE\b)', '🇮🇪', 'Ирландия'),
    (r'(norway|oslo|\bNO\b)', '🇳🇴', 'Норвегия'),
    (r'(denmark|copenhagen|\bDK\b)', '🇩🇰', 'Дания'),
    (r'(belgium|brussels|\bBE\b)', '🇧🇪', 'Бельгия'),
    (r'(portugal|lisbon|\bPT\b)', '🇵🇹', 'Португалия'),
    (r'(greece|athens|\bGR\b)', '🇬🇷', 'Греция'),
    (r'(israel|tel aviv|\bIL\b)', '🇮🇱', 'Израиль'),
    (r'(moldova|chisinau|\bMD\b)', '🇲🇩', 'Молдова'),
    (r'(armenia|yerevan|\bAM\b)', '🇦🇲', 'Армения'),
    (r'(georgia|tbilisi|\bGE\b)', '🇬🇪', 'Грузия'),
    (r'(uzbekistan|tashkent|\bUZ\b)', '🇺🇿', 'Узбекистан'),
    (r'(vietnam|\bVN\b)', '🇻🇳', 'Вьетнам'),
    (r'(thailand|bangkok|\bTH\b)', '🇹🇭', 'Таиланд'),
    (r'(taiwan|\bTW\b)', '🇹🇼', 'Тайвань'),
    (r'(russia|moscow|\bRU\b)', '🇷🇺', 'Россия')
]
emoji_to_name = {emoji: name for _, emoji, name in countries}
flag_re = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

final_links = []
xray_outbounds = []

def parse_to_xray_outbound(link, tag):
    try:
        parsed = urllib.parse.urlparse(link)
        proto = parsed.scheme
        host = parsed.hostname
        port = parsed.port
        user = parsed.username
        params = dict(urllib.parse.parse_qsl(parsed.query))
        
        if proto == 'vless':
            out = {
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": host,
                        "port": port,
                        "users": [{"id": user, "encryption": params.get("encryption", "none"), "flow": params.get("flow", "")}]
                    }]
                },
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": params.get("security", "none")
                }
            }
            if out["streamSettings"]["security"] == "tls":
                out["streamSettings"]["tlsSettings"] = {"serverName": params.get("sni", host), "allowInsecure": True}
            elif out["streamSettings"]["security"] == "reality":
                out["streamSettings"]["realitySettings"] = {
                    "serverName": params.get("sni", ""),
                    "fingerprint": params.get("fp", "chrome"),
                    "publicKey": params.get("pbk", ""),
                    "shortId": params.get("sid", "")
                }
            if out["streamSettings"]["network"] == "ws":
                out["streamSettings"]["wsSettings"] = {"path": params.get("path", "/"), "headers": {"Host": params.get("host", host)}}
            elif out["streamSettings"]["network"] == "grpc":
                out["streamSettings"]["grpcSettings"] = {"serviceName": params.get("serviceName", "")}
            return out
        elif proto == 'trojan':
            return {
                "tag": tag,
                "protocol": "trojan",
                "settings": {"servers": [{"address": host, "port": port, "password": user}]},
                "streamSettings": {
                    "network": params.get("type", "tcp"),
                    "security": "tls",
                    "tlsSettings": {"serverName": params.get("sni", host), "allowInsecure": True}
                }
            }
    except Exception:
        return None
    return None

for idx, (orig_link, base_link, host, port) in enumerate(alive_servers):
    decoded = urllib.parse.unquote(orig_link)
    
    flag_match = flag_re.search(decoded)
    flag = flag_match.group(0) if flag_match else ""
    country_ru = emoji_to_name.get(flag, "")
    
    if not country_ru:
        for pattern, emoji, name in countries:
            if re.search(pattern, decoded, re.IGNORECASE):
                flag = emoji
                country_ru = name
                break
                
    if not country_ru:
        flag = "🌐"
        country_ru = "Мир"
        
    clean_base = re.sub(r'[?&](remarks|name)=.*', '', base_link)
    final_links.append(f"{clean_base}#qwils [UPDATE] {flag} : {country_ru}")
    
    if len(xray_outbounds) < 150:
        ob = parse_to_xray_outbound(clean_base, f"node_{idx}")
        if ob:
            xray_outbounds.append(ob)

payload = "\n".join(final_links)
b64_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
with open("subscription.txt", "w", encoding="utf-8") as f:
    f.write(b64_payload)

def build_xray_json(remarks, nodes, use_white_lists=False):
    tags = [n["tag"] for n in nodes]
    routing_rules = []
    
    if use_white_lists:
        ru_domains = [
            "regexp:.*\\.ru$", "regexp:.*\\.рф$", "regexp:.*\\.su$",
            "geosite:category-ru", "geosite:yandex", "geosite:vk", "geosite:mailru",
            "domain:gosuslugi.ru", "domain:sberbank.ru", "domain:tbank.ru", "domain:vtb.ru",
            "domain:alfabank.ru", "domain:ozon.ru", "domain:wildberries.ru", "domain:avito.ru",
            "domain:kinopoisk.ru", "domain:yandex.net", "domain:ya.ru", "domain:vk.com",
            "domain:ok.ru", "domain:dzen.ru", "domain:rutube.ru", "domain:mos.ru",
            "domain:nalog.gov.ru", "domain:pochta.ru", "domain:rzd.ru", "domain:aeroflot.ru",
            "domain:dns-shop.ru", "domain:citilink.ru", "domain:mvideo.ru", "domain:magnit.ru",
            "domain:x5.ru", "domain:lenta.com", "domain:hh.ru", "domain:habr.com",
            "domain:pikabu.ru", "domain:2gis.ru", "domain:gismeteo.ru", "domain:rbc.ru",
            "domain:ria.ru", "domain:tass.ru", "domain:lenta.ru", "domain:gazeta.ru",
            "domain:kommersant.ru", "domain:kp.ru", "domain:iz.ru", "domain:rt.com",
            "domain:1tv.ru", "domain:ntv.ru", "domain:matchtv.ru", "domain:ivi.ru",
            "domain:okko.tv", "domain:wink.ru", "domain:kion.ru", "domain:start.ru",
            "domain:premier.one", "domain:more.tv", "domain:smotrim.ru", "domain:livejournal.com",
            "domain:stepik.org", "domain:uchi.ru", "domain:resh.edu.ru", "domain:sber.ru",
            "domain:tinkoff.ru", "domain:raiffeisen.ru", "domain:gazprombank.ru", "domain:psbank.ru",
            "domain:sovcombank.ru", "domain:open.ru", "domain:pochtabank.ru", "domain:mts.ru",
            "domain:megafon.ru", "domain:beeline.ru", "domain:tele2.ru", "domain:yota.ru",
            "domain:rostelecom.ru", "domain:dom.ru", "domain:mgts.ru", "domain:reg.ru",
            "domain:nic.ru", "domain:timeweb.com", "domain:selectel.ru", "domain:vkvideo.ru",
            "domain:yandex.com", "domain:yastatic.net", "domain:userapi.com", "domain:vk-portal.net"
        ]
        routing_rules.append({
            "type": "field",
            "domain": ru_domains,
            "outboundTag": "direct"
        })
        routing_rules.append({
            "type": "field",
            "ip": ["geoip:ru", "geoip:private"],
            "outboundTag": "direct"
        })

    routing_rules.append({
        "type": "field",
        "network": "tcp,udp",
        "balancerTag": "auto_fastest"
    })

    config = {
        "remarks": remarks,
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}},
            {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http"}
        ],
        "outbounds": nodes + [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "observatory": {
            "subjectSelector": tags,
            "probeURL": "http://cloudflare.com",
            "probeInterval": "30s"
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [
                {
                    "tag": "auto_fastest",
                    "selector": tags,
                    "strategy": {"type": "leastPing"}
                }
            ],
            "rules": routing_rules
        }
    }
    return json.dumps(config, ensure_ascii=False, indent=2)

if xray_outbounds:
    with open("auto_eu.json", "w", encoding="utf-8") as f:
        f.write(build_xray_json("Авто 🇪🇺", xray_outbounds, use_white_lists=False))

    chunk_size = 10
    for idx in range(5):
        chunk = xray_outbounds[idx * chunk_size : (idx + 1) * chunk_size]
        if not chunk:
            chunk = xray_outbounds[:chunk_size]
        with open(f"auto_bs_{idx + 1}.json", "w", encoding="utf-8") as f:
            f.write(build_xray_json(f"Авто БС #{idx + 1}", chunk, use_white_lists=True))

print("=== Готово! Все подписки и JSON-балансировщики успешно созданы ===")
EOF
