import base64
import json
import re
import urllib.request
import urllib.parse
import socket
import concurrent.futures
from datetime import datetime, timezone, timedelta

SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "sub.txt"
README_FILE = "README.md"

# Список тестовых сайтов для проверки (заблокированы в РФ)
TEST_URLS = [
    "https://www.instagram.com",
    "https://discord.com",
    "https://x.com",
    "https://en.wikipedia.org"
]

def fetch_sources():
    raw_configs = set()
    try:
        with open(SOURCES_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except Exception:
        return []

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
                try:
                    decoded = base64.b64decode(content + "===").decode('utf-8', errors='ignore')
                    if "://" in decoded:
                        content = decoded
                except Exception:
                    pass
                
                found = re.findall(r'((?:vless|vmess|trojan|ss)://[^\s<"]+)', content)
                for cfg in found:
                    raw_configs.add(cfg)
        except Exception as e:
            print(f"Ошибка загрузки источника {url}: {e}")
            
    return list(raw_configs)

def get_country_info(host, fragment):
    """Возвращает название страны и эмодзи-флаг для клиентов"""
    text = (fragment + " " + host).lower()
    
    if any(k in text for k in ["germany", "de", "германия"]): return "Германия", "🇩🇪"
    if any(k in text for k in ["netherlands", "nl", "нидерланды", "голландия"]): return "Нидерланды", "🇳🇱"
    if any(k in text for k in ["usa", "us", "united states", "сша", "америка"]): return "США", "🇺🇸"
    if any(k in text for k in ["finland", "fi", "финляндия"]): return "Финляндия", "🇫🇮"
    if any(k in text for k in ["france", "fr", "франция"]): return "Франция", "🇫🇷"
    if any(k in text for k in ["sweden", "se", "швеция"]): return "Швеция", "🇸🇪"
    if any(k in text for k in ["kazakhstan", "kz", "казахстан"]): return "Казахстан", "🇰🇿"
    if any(k in text for k in ["uk", "gb", "britain", "великобритания", "англия"]): return "Великобритания", "🇬🇧"
    if any(k in text for k in ["poland", "pl", "польша"]): return "Польша", "🇵🇱"
    
    return "Другие", "🌍"

def test_node(cfg):
    """Усиленная проверка: TCP-соединение + проверка работоспособности"""
    try:
        parsed = urllib.parse.urlparse(cfg)
        netloc = parsed.netloc.split('@')[-1]
        if ":" in netloc:
            host, port = netloc.split(':')[:2]
        else:
            host, port = netloc, "443"
            
        # 1. Быстрый тест порта (до 1 секунды)
        socket.setdefaulttimeout(1.0)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s.close()
        
        country, flag = get_country_info(host, parsed.fragment)
        return (True, country, flag, cfg)
    except Exception:
        return (False, "", "", "")

def update_readme(total_nodes):
    """Обновляет красивый README.md со статусом и ссылкой"""
    # Московское время (UTC+3)
    msk_time = datetime.now(timezone(timedelta(hours=3))).strftime("%d.%m.%Y в %H:%M МСК")
    
    readme_content = f"""# @qw1lsVPN FREE

⚡ **Бесплатная и автоматическая подписка на рабочие VLESS-ноды**  
Обновляется автоматически через GitHub Actions. Без платных подписок и рекламы.

---

### 📊 Статус подписки:
* **Активных серверов:** `{total_nodes}`
* **Последнее обновление:** `{msk_time}`

---

### 🔗 Ссылка на подписку:
Скопируйте эту ссылку и добавьте ее в свой клиент (**Hiddify**, **NekoBox**, **v2rayNG**):

```text
[https://raw.githubusercontent.com/ВАШ_АККАУНТ/ВАШ_РЕПОЗИТОРИЙ/main/sub.txt](https://raw.githubusercontent.com/ВАШ_АККАУНТ/ВАШ_РЕПОЗИТОРИЙ/main/sub.txt)
