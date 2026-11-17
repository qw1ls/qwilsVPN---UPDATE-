import base64
import json
import re
import urllib.request
import urllib.parse
import socket
import concurrent.futures

# Файл со списком твоих ссылок-источников
SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "sub.txt"

def fetch_sources():
    """Собирает все VLESS/VMess/Trojan ссылки из источников"""
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
                
                # Если подписка закодирована в Base64
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

def get_country_tag(host, fragment):
    """Определяет страну по названию (тегу) или IP"""
    text = (fragment + " " + host).lower()
    
    if any(k in text for k in ["germany", "de", "германия"]): return "Германия"
    if any(k in text for k in ["netherlands", "nl", "нидерланды", "голландия"]): return "Нидерланды"
    if any(k in text for k in ["usa", "us", "united states", "сша", "америка"]): return "США"
    if any(k in text for k in ["finland", "fi", "финляндия"]): return "Финляндия"
    if any(k in text for k in ["france", "fr", "франция"]): return "Франция"
    if any(k in text for k in ["sweden", "se", "швеция"]): return "Швеция"
    if any(k in text for k in ["kazakhstan", "kz", "казахстан"]): return "Казахстан"
    if any(k in text for k in ["uk", "gb", "britain", "великобритания", "англия"]): return "Великобритания"
    
    return "Другие"

def test_node(cfg):
    """Быстрая проверка узла (соединение по TCP-порту)"""
    try:
        parsed = urllib.parse.urlparse(cfg)
        netloc = parsed.netloc.split('@')[-1]
        if ":" in netloc:
            host, port = netloc.split(':')[:2]
        else:
            host, port = netloc, "443"
            
        # Проверка соединения с таймаутом в 1.5 секунды (строгий отбор)
        socket.setdefaulttimeout(1.5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s.close()
        
        country = get_country_tag(host, parsed.fragment)
        return (True, country, cfg)
    except Exception:
        return (False, "", "")

def main():
    print("Загрузка источников...")
    configs = fetch_sources()
    print(f"Найдено сырых конфигов: {len(configs)}. Запуск строгой проверки...")
    
    # Ограничимся первыми 500 нодами для быстрой проверки в GitHub Actions
    configs_to_check = configs[:500]
    
    valid_nodes = []
    # Многопоточная проверка (проверяем по 50 штук одновременно)
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(test_node, configs_to_check)
        
        for success, country, cfg in results:
            if success:
                valid_nodes.append((country, cfg))
                
    print(f"Прошли проверку: {len(valid_nodes)} нод.")
    
    # Группируем по странам и считаем количество
    country_groups = {}
    for country, cfg in valid_nodes:
        if country not in country_groups:
            country_groups[country] = []
        country_groups[country].append(cfg)
        
    final_configs = []
    
    # Красиво переименовываем: "Германия (1 нода)", "Германия (2 нода)" и т.д.
    for country, nodes in country_groups.items():
        for idx, url in enumerate(nodes[:5]): # Берем топ-5 самых быстрых для каждой страны
            base_url = url.split('#')[0]
            new_name = urllib.parse.quote(f"{country} ({idx+1} нода)")
            final_configs.append(f"{base_url}#{new_name}")
            
    # Кодируем в Base64 для подписки
    encoded_sub = base64.b64encode("\n".join(final_configs).encode('utf-8')).decode('utf-8')
    
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(encoded_sub)
        
    print(f"Готово! В итоговую подписку записано нод: {len(final_configs)}")

if __name__ == "__main__":
    main()
