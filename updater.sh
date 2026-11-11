#!/bin/bash

python3 - << 'EOF'
import urllib.request
import urllib.parse
import re
import base64
import concurrent.futures

# Маскировка ссылок пробелами
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
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception:
        return ""

print("=== Параллельное скачивание всех 30 источников ===")
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    texts = list(executor.map(fetch_url, urls))

raw_data = "\n".join(texts)

# Вытаскиваем только vless, ss и trojan (без hysteria и vmess)
links = set(re.findall(r'(?:vless|ss|trojan)://[^\s"\'<>]+', raw_data))
print(f"Найдено уникальных ссылок: {len(links)}")

country_map = [
    (r'(netherlands|holland|\bNL\b)', '🇳🇱'),
    (r'(united states|america|\bUS\b|\bUSA\b)', '🇺🇸'),
    (r'(germany|nuremberg|frankfurt|\bDE\b)', '🇩🇪'),
    (r'(finland|helsinki|\bFI\b)', '🇫🇮'),
    (r'(france|roubaix|\bFR\b)', '🇫🇷'),
    (r'(sweden|\bSE\b)', '🇸🇪'),
    (r'(poland|warsaw|wroclaw|\bPL\b)', '🇵🇱'),
    (r'(kazakhstan|\bKZ\b)', '🇰🇿'),
    (r'(japan|inzai|\bJP\b)', '🇯🇵'),
    (r'(korea|\bKR\b)', '🇰🇷'),
    (r'(singapore|\bSG\b)', '🇸🇬'),
    (r'(turkey|sultanbeyli|\bTR\b)', '🇹🇷'),
    (r'(hong kong|\bHK\b)', '🇭🇰'),
    (r'(united arab|emirates|\bAE\b)', '🇦🇪'),
    (r'(united kingdom|london|manchester|\bUK\b|\bGB\b)', '🇬🇧'),
    (r'(latvia|\bLV\b)', '🇱🇻'),
    (r'(estonia|\bEE\b)', '🇪🇪'),
    (r'(lithuania|\bLT\b)', '🇱🇹'),
    (r'(austria|\bAT\b)', '🇦🇹'),
    (r'(switzerland|\bCH\b)', '🇨🇭'),
    (r'(canada|montreal|\bCA\b)', '🇨🇦'),
    (r'(spain|\bES\b)', '🇪🇸'),
    (r'(italy|\bIT\b)', '🇮🇹'),
    (r'(ukraine|\bUA\b)', '🇺🇦'),
    (r'(belarus|\bBY\b)', '🇧🇾'),
    (r'(czechia|czech|\bCZ\b)', '🇨🇿'),
    (r'(india|delhi|\bIN\b)', '🇮🇳')
]

flag_re = re.compile(r'[\U0001F1E6-\U0001F1FF]{2}')
final_links = []

for link in sorted(links):
    decoded = urllib.parse.unquote(link)
    
    # Ищем флаг-смайлик в декодированной строке
    flag_match = flag_re.search(decoded)
    flag = flag_match.group(0) if flag_match else ""
    
    if not flag:
        for pattern, emoji in country_map:
            if re.search(pattern, decoded, re.IGNORECASE):
                flag = emoji
                break
    if not flag:
        flag = "🌐"
        
    # Полностью срезаем старое имя
    base_link = link.split('#')[0]
    base_link = re.sub(r'%23.*', '', base_link)
    base_link = re.sub(r'[?&](remarks|name)=.*', '', base_link)
    
    final_links.append(f"{base_link}#qwils [UPDATE] {flag}")

payload = "\n".join(final_links)
b64_payload = base64.b64encode(payload.encode('utf-8')).decode('utf-8')

with open("subscription.txt", "w", encoding="utf-8") as f:
    f.write(b64_payload)

print(f"=== Готово! Упаковано {len(final_links)} серверов ===")
EOF
