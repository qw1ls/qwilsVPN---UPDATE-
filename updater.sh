#!/bin/bash
set -e

echo "=== 1. Скачивание ядра Xray ==="
curl -sL -o xray.zip "https://github.com"
unzip -q -o xray.zip xray
chmod +x xray
rm -f xray.zip

python3 - << 'EOF'
import urllib.request, urllib.parse, subprocess, time, re, json, base64, os, concurrent.futures

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
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

print("=== 2. Сбор источников ===")
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
    raw_data = "\n".join(ex.map(fetch, urls))

raw_links = set(re.findall(r'(?:vless|trojan)://[^\s"\'<>]+', raw_data))
unique = {}
for link in raw_links:
    base = re.sub(r'%23.*', '', link.split('#')[0])
    m = re.search(r'@([^:/?#]+):(\d+)', base)
    if m and m.group(1) not in ('127.0.0.1', '0.0.0.0', 'localhost'):
        key = f"{m.group(1)}:{m.group(2)}"
        if key not in unique:
            unique[key] = (link, base)

candidates = list(unique.values())[:500]
print(f"Отобрано кандидатов для Xray-теста: {len(candidates)}")

def to_outbound(link, tag):
    try:
        p = urllib.parse.urlparse(link)
        q = dict(urllib.parse.parse_qsl(p.query))
        if p.scheme == 'vless':
            out = {
                "tag": tag, "protocol": "vless",
                "settings": {"vnext": [{"address": p.hostname, "port": p.port, "users": [{"id": p.username, "encryption": q.get("encryption", "none"), "flow": q.get("flow", "")}]}]},
                "streamSettings": {"network": q.get("type", "tcp"), "security": q.get("security", "none")}
            }
            if out["streamSettings"]["security"] == "tls":
                out["streamSettings"]["tlsSettings"] = {"serverName": q.get("sni", p.hostname), "allowInsecure": True}
            elif out["streamSettings"]["security"] == "reality":
                out["streamSettings"]["realitySettings"] = {"serverName": q.get("sni", ""), "fingerprint": q.get("fp", "chrome"), "publicKey": q.get("pbk", ""), "shortId": q.get("sid", "")}
            if out["streamSettings"]["network"] == "ws":
                out["streamSettings"]["wsSettings"] = {"path": q.get("path", "/"), "headers": {"Host": q.get("host", p.hostname)}}
            elif out["streamSettings"]["network"] == "grpc":
                out["streamSettings"]["grpcSettings"] = {"serviceName": q.get("serviceName", "")}
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
def test_xray(item):
    idx, (orig, base) = item
    ob = to_outbound(base, "proxy")
    if not ob:
        return None
    port = 20000 + idx
    cfg_path = f"/tmp/x_{idx}.json"
    with open(cfg_path, "w") as f:
        json.dump({"log": {"loglevel": "none"}, "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "http"}], "outbounds": [ob]}, f)
    proc = subprocess.Popen(["./xray", "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.4)
    ok = False
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': f'http://127.0.0.1:{port}', 'https': f'http://127.0.0.1:{port}'}))
        with opener.open("http://cloudflare.com", timeout=4) as r:
            if r.status in (200, 204):
                ok = True
    except Exception:
        pass
    finally:
        proc.terminate()
        proc.wait()
        if os.path.exists(cfg_path):
            os.remove(cfg_path)
    return (orig, base, ob) if ok else None

print("=== 3. Запуск проверки трафика через Xray ===")
alive = []
with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
    for r in ex.map(test_xray, enumerate(candidates)):
        if r:
            alive.append(r)

print(f"Выжило рабочих серверов: {len(alive)}")

countries = [
    (r'(netherlands|\bNL\b)', '🇳🇱', 'Нидерланды'), (r'(united states|\bUS\b|\bUSA\b)', '🇺🇸', 'США'),
    (r'(germany|frankfurt|\bDE\b)', '🇩🇪', 'Германия'), (r'(finland|helsinki|\bFI\b)', '🇫🇮', 'Финляндия'),
    (r'(france|paris|roubaix|\bFR\b)', '🇫🇷', 'Франция'), (r'(sweden|\bSE\b)', '🇸🇪', 'Швеция'),
    (r'(poland|warsaw|wroclaw|\bPL\b)', '🇵🇱', 'Польша'), (r'(kazakhstan|\bKZ\b)', '🇰🇿', 'Казахстан'),
    (r'(japan|tokyo|\bJP\b)', '🇯🇵', 'Япония'), (r'(korea|seoul|\bKR\b)', '🇰🇷', 'Южная Корея'),
    (r'(singapore|\bSG\b)', '🇸🇬', 'Сингапур'), (r'(turkey|\bTR\b)', '🇹🇷', 'Турция'),
    (r'(hong kong|\bHK\b)', '🇭🇰', 'Гонконг'), (r'(emirates|dubai|\bAE\b)', '🇦🇪', 'ОАЭ'),
    (r'(united kingdom|london|manchester|\bUK\b|\bGB\b)', '🇬🇧', 'Великобритания'),
    (r'(latvia|\bLV\b)', '🇱🇻', 'Латвия'), (r'(estonia|\bEE\b)', '🇪🇪', 'Эстония'),
    (r'(lithuania|\bLT\b)', '🇱🇹', 'Литва'), (r'(austria|\bAT\b)', '🇦🇹', 'Австрия'),
    (r'(switzerland|\bCH\b)', '🇨🇭', 'Швейцария'), (r'(canada|montreal|\bCA\b)', '🇨🇦', 'Канада'),
    (r'(spain|\bES\b)', '🇪🇸', 'Испания'), (r'(italy|\bIT\b)', '🇮🇹', 'Италия'),
    (r'(ukraine|\bUA\b)', '🇺🇦', 'Украина'), (r'(belarus|\bBY\b)', '🇧🇾', 'Беларусь'),
    (r'(czech|\bCZ\b)', '🇨🇿', 'Чехия'), (r'(india|\bIN\b)', '🇮🇳', 'Индия'),
    (r'(australia|\bAU\b)', '🇦🇺', 'Австралия'), (r'(brazil|\bBR\b)', '🇧🇷', 'Бразилия'),
    (r'(bulgaria|\bBG\b)', '🇧🇬', 'Болгария'), (r'(romania|\bRO\b)', '🇷🇴', 'Румыния'),
    (r'(ireland|\bIE\b)', '🇮🇪', 'Ирландия'), (r'(norway|\bNO\b)', '🇳🇴', 'Норвегия'),
    (r'(denmark|\bDK\b)', '🇩🇰', 'Дания'), (r'(belgium|\bBE\b)', '🇧🇪', 'Бельгия'),
    (r'(portugal|\bPT\b)', '🇵🇹', 'Португалия'), (r'(greece|\bGR\b)', '🇬🇷', 'Греция'),
    (r'(israel|\bIL\b)', '🇮🇱', 'Израиль'), (r'(moldova|\bMD\b)', '🇲🇩', 'Молдова'),
    (r'(armenia|\bAM\b)', '🇦🇲', 'Армения'), (r'(georgia|\bGE\b)', '🇬🇪', 'Грузия'),
    (r'(uzbekistan|\bUZ\b)', '🇺🇿', 'Узбекистан'), (r'(vietnam|\bVN\b)', '🇻🇳', 'Вьетнам'),
    (r'(thailand|\bTH\b)', '🇹🇭', 'Таиланд'), (r'(taiwan|\bTW\b)', '🇹🇼', 'Тайвань'),
    (r'(russia|moscow|\bRU\b)', '🇷🇺', 'Россия')
]

emoji_map = {e: n for _, e, n in countries}
flag_re = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')

title_b64 = base64.b64encode("qwils UPDATE LTE".encode('utf-8')).decode('utf-8')
final_links = [f"#profile-title: base64:{title_b64}"]
outbounds = []

for i, (orig, base, ob) in enumerate(alive):
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
    ob["tag"] = f"node_{i}"
    outbounds.append(ob)

with open("subscription.txt", "w", encoding="utf-8") as f:
    f.write(base64.b64encode("\n".join(final_links).encode('utf-8')).decode('utf-8'))

def make_json(title, nodes, bs=False):
    tags = [n["tag"] for n in nodes]
    rules = []
    if bs:
        ru = ["regexp:.*\\.ru$", "regexp:.*\\.рф$", "regexp:.*\\.su$", "geosite:category-ru", "geosite:yandex", "geosite:vk", "geosite:mailru", "domain:gosuslugi.ru", "domain:sberbank.ru", "domain:tbank.ru", "domain:vtb.ru", "domain:ozon.ru", "domain:wildberries.ru", "domain:avito.ru", "domain:kinopoisk.ru", "domain:vk.com", "domain:ya.ru", "domain:rutube.ru", "domain:dzen.ru"]
        rules.append({"type": "field", "domain": ru, "outboundTag": "direct"})
        rules.append({"type": "field", "ip": ["geoip:ru", "geoip:private"], "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "auto"})
    return json.dumps({
        "remarks": title, "log": {"loglevel": "warning"},
        "inbounds": [{"tag": "socks", "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}}, {"tag": "http", "port": 10809, "listen": "127.0.0.1", "protocol": "http"}],
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
EOF
rm -f xray
