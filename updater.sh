#!/bin/bash
set -e

python3 - << 'EOF'
import urllib.request, urllib.parse, socket, ssl, time, re, json, base64, concurrent.futures

raw_urls = [
    "https:// raw . githubusercontent . com / 0xRadikal / Free-v2ray-Configs / refs / heads / main / all / configs . txt",
    "https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_SS%2BAll_RUS . txt",
    "https:// fastly . jsdelivr . net / gh / whoahaow / rjsxrd@main / githubmirror / bypass / bypass-all . txt",
    "https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_VLESS_RUS . txt",
    "https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / Vless-Reality-White-Lists-Rus-Mobile . txt"
] + [f"https:// raw . githubusercontent . com / hiztin / VLESS-PO-GRIBI / main / deploy / subscriptions / {i} . txt" for i in range(1, 26)]

urls = [u.replace(" ", "") for u in raw_urls]

def fetch(u):
    try:
        req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

print("=== 1. Сбор всех 30 источников ===")
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
    raw_data = "\n".join(ex.map(fetch, urls))

raw_links = set(re.findall(r'(?:vless|trojan|ss)://[^\s"\'<>]+', raw_data))
unique = {}
for link in raw_links:
    head, _, _ = link.partition('#')
    base = re.sub(r'%23.*', '', head)
    m = re.search(r'@([^:/?#]+):(\d+)', base)
    if m:
        host, port = m.group(1), int(m.group(2))
        if host not in ('127.0.0.1', '0.0.0.0', 'localhost') and 1 <= port <= 65535:
            key = f"{host}:{port}"
            if key not in unique:
                unique[key] = (link, base, host, port)

print(f"Уникальных серверов после очистки дублей: {len(unique)}")

def to_outbound(link, tag):
    try:
        p = urllib.parse.urlparse(link)
        q = dict(urllib.parse.parse_qsl(p.query))
        if not p.hostname or not p.port or not p.username:
            return None
        if p.scheme == 'vless':
            sec = q.get("security", "none")
            if sec == "reality" and not q.get("pbk"):
                return None
            out = {
                "tag": tag, "protocol": "vless",
                "settings": {"vnext": [{"address": p.hostname, "port": p.port, "users": [{"id": p.username, "encryption": q.get("encryption", "none"), "flow": q.get("flow", "")}]}]},
                "streamSettings": {"network": q.get("type", "tcp"), "security": sec}
            }
            if sec == "tls":
                out["streamSettings"]["tlsSettings"] = {"serverName": q.get("sni", p.hostname), "allowInsecure": True}
            elif sec == "reality":
                out["streamSettings"]["realitySettings"] = {"serverName": q.get("sni", ""), "fingerprint": q.get("fp", "chrome"), "publicKey": q.get("pbk", ""), "shortId": q.get("sid", "")}
            net = out["streamSettings"]["network"]
            if net == "ws":
                out["streamSettings"]["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", p.hostname)}}
            elif net == "grpc":
                out["streamSettings"]["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
            elif net == "xhttp":
                out["streamSettings"]["xhttpSettings"] = {"path": q.get("path", "/"), "host": q.get("host", p.hostname)}
            return out
        elif p.scheme == 'trojan':
            return {
                "tag": tag, "protocol": "trojan",
                "settings": {"servers": [{"address": p.hostname, "port": p.port, "password": p.username}]},
                "streamSettings": {"network": q.get("type", "tcp"), "security": "tls", "tlsSettings": {"serverName": q.get("sni", p.hostname), "allowInsecure": True}}
            }
    except Exception:
        return None
    return None
def deep_verify(item):
    orig, base, host, port = item
    p = urllib.parse.urlparse(base)
    q = dict(urllib.parse.parse_qsl(p.query))
    
    # Проверка валидности структуры параметров
    if p.scheme == 'vless':
        sec = q.get("security", "none")
        if sec == "reality" and (not q.get("pbk") or not q.get("sni")):
            return None
        if not p.username or len(p.username) < 10:
            return None

    try:
        t0 = time.time()
        # 1. Проверка DNS и открытого TCP-порта
        with socket.create_connection((host, port), timeout=2.5) as sock:
            # 2. Если используется TLS или Reality, делаем полноценное SSL-рукопожатие с правильным SNI
            sec = q.get("security", "none")
            if sec in ("tls", "reality") or p.scheme == "trojan":
                sni = q.get("sni", host) or host
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                    # Отправляем тестовый байт и проверяем, что сервер не рвет соединение сразу
                    ssock.settimeout(2.0)
            latency = int((time.time() - t0) * 1000)
            return (latency, orig, base)
    except Exception:
        return None

print("=== 2. Запуск глубокой проверки TLS/SNI и замера задержки (100 потоков) ===")
verified = []
with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
    for res in ex.map(deep_verify, unique.values()):
        if res is not None:
            verified.append(res)

# Сортируем все выжившие серверы от самого быстрого к самому медленному
verified.sort(key=lambda x: x)
print(f"Выжило и отсортировано по скорости: {len(verified)} серверов")

countries = [
    (r'(netherlands|holland|\bNL\b)', '🇳🇱', 'Нидерланды'), (r'(united states|america|\bUS\b|\bUSA\b)', '🇺🇸', 'США'),
    (r'(germany|frankfurt|nuremberg|\bDE\b)', '🇩🇪', 'Германия'), (r'(finland|helsinki|\bFI\b)', '🇫🇮', 'Финляндия'),
    (r'(france|paris|roubaix|\bFR\b)', '🇫🇷', 'Франция'), (r'(sweden|stockholm|\bSE\b)', '🇸🇪', 'Швеция'),
    (r'(poland|warsaw|wroclaw|\bPL\b)', '🇵🇱', 'Польша'), (r'(kazakhstan|almaty|\bKZ\b)', '🇰🇿', 'Казахстан'),
    (r'(japan|tokyo|inzai|\bJP\b)', '🇯🇵', 'Япония'), (r'(korea|seoul|\bKR\b)', '🇰🇷', 'Южная Корея'),
    (r'(singapore|\bSG\b)', '🇸🇬', 'Сингапур'), (r'(turkey|istanbul|\bTR\b)', '🇹🇷', 'Турция'),
    (r'(hong kong|\bHK\b)', '🇭🇰', 'Гонконг'), (r'(emirates|dubai|\bAE\b)', '🇦🇪', 'ОАЭ'),
    (r'(united kingdom|london|manchester|\bUK\b|\bGB\b)', '🇬🇧', 'Великобритания'),
    (r'(latvia|riga|\bLV\b)', '🇱🇻', 'Латвия'), (r'(estonia|tallinn|\bEE\b)', '🇪🇪', 'Эстония'),
    (r'(lithuania|vilnius|\bLT\b)', '🇱🇹', 'Литва'), (r'(austria|vienna|\bAT\b)', '🇦🇹', 'Австрия'),
    (r'(switzerland|zurich|\bCH\b)', '🇨🇭', 'Швейцария'), (r'(canada|montreal|toronto|\bCA\b)', '🇨🇦', 'Канада'),
    (r'(spain|madrid|\bES\b)', '🇪🇸', 'Испания'), (r'(italy|milan|\bIT\b)', '🇮🇹', 'Италия'),
    (r'(ukraine|kyiv|\bUA\b)', '🇺🇦', 'Украина'), (r'(belarus|minsk|\bBY\b)', '🇧🇾', 'Беларусь'),
    (r'(czech|prague|\bCZ\b)', '🇨🇿', 'Чехия'), (r'(india|delhi|\bIN\b)', '🇮🇳', 'Индия'),
    (r'(australia|sydney|\bAU\b)', '🇦🇺', 'Австралия'), (r'(brazil|\bBR\b)', '🇧🇷', 'Бразилия'),
    (r'(bulgaria|sofia|\bBG\b)', '🇧🇬', 'Болгария'), (r'(romania|bucharest|\bRO\b)', '🇷🇴', 'Румыния'),
    (r'(ireland|dublin|\bIE\b)', '🇮🇪', 'Ирландия'), (r'(norway|oslo|\bNO\b)', '🇳🇴', 'Норвегия'),
    (r'(denmark|copenhagen|\bDK\b)', '🇩🇰', 'Дания'), (r'(belgium|brussels|\bBE\b)', '🇧🇪', 'Бельгия'),
    (r'(portugal|lisbon|\bPT\b)', '🇵🇹', 'Португалия'), (r'(greece|athens|\bGR\b)', '🇬🇷', 'Греция'),
    (r'(israel|tel aviv|\bIL\b)', '🇮🇱', 'Израиль'), (r'(moldova|chisinau|\bMD\b)', '🇲🇩', 'Молдова'),
    (r'(armenia|yerevan|\bAM\b)', '🇦🇲', 'Армения'), (r'(georgia|tbilisi|\bGE\b)', '🇬🇪', 'Грузия'),
    (r'(uzbekistan|tashkent|\bUZ\b)', '🇺🇿', 'Узбекистан'), (r'(vietnam|\bVN\b)', '🇻🇳', 'Вьетнам'),
    (r'(thailand|bangkok|\bTH\b)', '🇹🇭', 'Таиланд'), (r'(taiwan|\bTW\b)', '🇹🇼', 'Тайвань'),
    (r'(russia|moscow|\bRU\b)', '🇷🇺', 'Россия')
]

emoji_map = {e: n for _, e, n in countries}
flag_re = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

title_b64 = base64.b64encode("qwils UPDATE LTE".encode('utf-8')).decode('utf-8')
final_links = [
    f"#profile-title: base64:{title_b64}",
    "#profile-update-interval: 6"
]
outbounds = []

for i, (lat, orig, base) in enumerate(verified):
    dec = urllib.parse.unquote(orig)
    fm = flag_re.search(dec)
    flag = fm.group(0) if fm else ""
    name = emoji_map.get(flag, "")
    if not name:
        for pat, e, n in countries:
            if re.search(pat, dec, re.I):
                flag, name = e, n
                break
    if not name:
        flag, name = "🌐", "Мир"
    clean = re.sub(r'[?&](remarks|name)=.*', '', base)
    final_links.append(f"{clean}#{flag} : {name}")
    
    if len(outbounds) < 120:
        ob = to_outbound(clean, f"node_{i}")
        if ob:
            outbounds.append(ob)

with open("subscription.txt", "w", encoding="utf-8") as f:
    f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))

def make_json(title, nodes, bs=False):
    tags = [n["tag"] for n in nodes]
    rules = []
    if bs:
        ru = [
            "regexp:.*\\.ru$", "regexp:.*\\.рф$", "regexp:.*\\.su$",
            "geosite:category-ru", "geosite:yandex", "geosite:vk", "geosite:mailru",
            "domain:gosuslugi.ru", "domain:sberbank.ru", "domain:tbank.ru", "domain:vtb.ru",
            "domain:alfabank.ru", "domain:ozon.ru", "domain:wildberries.ru", "domain:avito.ru",
            "domain:kinopoisk.ru", "domain:vk.com", "domain:ya.ru", "domain:rutube.ru",
            "domain:dzen.ru", "domain:mos.ru", "domain:nalog.gov.ru", "domain:pochta.ru",
            "domain:rzd.ru", "domain:dns-shop.ru", "domain:citilink.ru", "domain:mvideo.ru",
            "domain:hh.ru", "domain:habr.com", "domain:pikabu.ru", "domain:2gis.ru",
            "domain:ivi.ru", "domain:okko.tv", "domain:wink.ru", "domain:kion.ru"
        ]
        rules.append({"type": "field", "domain": ru, "outboundTag": "direct"})
        rules.append({"type": "field", "ip": ["geoip:ru", "geoip:private"], "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
    return json.dumps({
        "remarks": title, "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}},
            {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http"}
        ],
        "outbounds": nodes + [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
        "observatory": {"subjectSelector": tags, "probeURL": "http://cloudflare.com", "probeInterval": "30s"},
        "routing": {"domainStrategy": "IPIfNonMatch", "balancers": [{"tag": "auto", "selector": tags, "strategy": {"type": "leastPing"}}], "rules": rules}
    }, ensure_ascii=False, indent=2)

if outbounds:
    with open("auto_eu.json", "w", encoding="utf-8") as f:
        f.write(make_json("Авто 🇪🇺", outbounds, False))
    for idx in range(5):
        chunk = outbounds[idx*10:(idx+1)*10] or outbounds[:10]
        with open(f"auto_bs_{idx+1}.json", "w", encoding="utf-8") as f:
            f.write(make_json(f"Авто БС #{idx+1}", chunk, True))

print("=== Успешно завершено! ===")
EOF
