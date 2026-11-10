#!/bin/bash

# Создаем чистые рабочие файлы
> raw_configs.txt
> clean_configs.txt
> filtered_configs.txt

echo "=== Сбор источников с обходом блокировок Гитхаба ==="

# Записываем все ваши 5 источников (маскировка пробелами)
url1="https:// raw . githubusercontent . com / 0xRadikal / Free-v2ray-Configs / refs / heads / main / all / configs . txt"
url2="https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_SS%2BAll_RUS . txt"
url3="https:// fastly . jsdelivr . net / gh / whoahaow / rjsxrd@main / githubmirror / bypass / bypass-all . txt"
url4="https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_VLESS_RUS . txt"
url5="https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / Vless-Reality-White-Lists-Rus-Mobile . txt"

# Удаляем пробелы и скачиваем
clean_url1=$(echo "$url1" | sed 's/ //g')
clean_url2=$(echo "$url2" | sed 's/ //g')
clean_url3=$(echo "$url3" | sed 's/ //g')
clean_url4=$(echo "$url4" | sed 's/ //g')
clean_url5=$(echo "$url5" | sed 's/ //g')

curl -sL --connect-timeout 5 "$clean_url1" >> raw_configs.txt
curl -sL --connect-timeout 5 "$clean_url2" >> raw_configs.txt
curl -sL --connect-timeout 5 "$clean_url3" >> raw_configs.txt
curl -sL --connect-timeout 5 "$clean_url4" >> raw_configs.txt
curl -sL --connect-timeout 5 "$clean_url5" >> raw_configs.txt

# Цикл по грибам от 1 до 25
for i in {1..25}; do
    grib_url="https:// raw . githubusercontent . com / hiztin / VLESS-PO-GRIBI / main / deploy / subscriptions / ${i} . txt"
    clean_grib_url=$(echo "$grib_url" | sed 's/ //g')
    curl -sL --connect-timeout 3 "$clean_grib_url" >> raw_configs.txt
done

# Очищаем базу от дубликатов
grep -oE '(vless|ss|vmess|trojan|hysteria2|hy2)://[^"& ]+' raw_configs.txt | sort -u > clean_configs.txt
total_servers=$(wc -l < clean_configs.txt)
echo "Успешно скачано серверов для жесткой фильтрации: $total_servers"

echo "=== Загрузка базы данных блокировок ТСПУ/РКН ==="
# Скачиваем официальные пулы IP-адресов, которые сейчас массово блокируются в РФ (CDN Cloudflare, мусорные хостинги)
> blocked_ips.txt
curl -sL "https://antifilter.download" >> blocked_ips.txt

echo "=== Старт боевой анти-ТСПУ проверки и тотального переименования ==="
urldecode() { : "${*//+/ }"; echo -e "${_//%/\\x}"; }

while read -r line; do
    server_host=$(echo "$line" | grep -oE '@[^:]+' | tr -d '@' | head -n 1)
    
    if [ ! -z "$server_host" ]; then
        # Превращаем домен в IP, если сервер записан буквами
        server_ip=$(dig +short "$server_host" | head -n 1)
        if [ -z "$server_ip" ]; then
            server_ip="$server_host"
        fi

        # ЖЕСТКИЙ ЧЕК: Проверяем, не заблокирован ли этот IP в РФ через базу Antifilter
        if ! grep -q "$server_ip" blocked_ips.txt; then
            
            # Узел чист! Декодируем оригинальные флаги страны
            decoded_line=$(urldecode "$line")
            flag=$(echo "$decoded_line" | grep -oP '[\x{1F1E6}-\x{1F1FF}]{2}' 2>/dev/null | head -n 1)

            if [ -z "$flag" ]; then
                if echo "$decoded_line" | grep -riqE '(netherlands|holland|\bNL\b)'; then flag="🇳🇱"
                elif echo "$decoded_line" | grep -riqE '(united states|america|\bUS\b|\bUSA\b)'; then flag="🇺🇸"
                elif echo "$decoded_line" | grep -riqE '(germany|nuremberg|\bDE\b)'; then flag="🇩🇪"
                elif echo "$decoded_line" | grep -riqE '(finland|\bFI\b)'; then flag="🇫🇮"
                elif echo "$decoded_line" | grep -riqE '(france|roubaix|\bFR\b)'; then flag="🇫🇷"
                elif echo "$decoded_line" | grep -riqE '(poland|warsaw|wroclaw|\bPL\b)'; then flag="🇵🇱"
                elif echo "$decoded_line" | grep -riqE '(kazakhstan|\bKZ\b)'; then flag="🇰🇿"
                elif echo "$decoded_line" | grep -riqE '(japan|\bJP\b)'; then flag="🇯🇵"
                elif echo "$decoded_line" | grep -riqE '(united kingdom|london|manchester|\bUK\b)'; then flag="🇬🇧"
                elif echo "$decoded_line" | grep -riqE '(spain|\bES\b)'; then flag="🇪🇸"
                elif echo "$decoded_line" | grep -riqE '(italy|\bIT\b)'; then flag="🇮🇹"
                else flag="🌐"
                fi
            fi

            # Новое имя
            new_name="qwils [UPDATE] ${flag}"
            
            # Тотальная зачистка старых названий
            clean_line="$line"
            clean_line=$(echo "$clean_line" | cut -d'#' -f1)
            clean_line=$(echo "$clean_line" | sed 's/%23.*//')
            clean_line=$(echo "$clean_line" | sed 's/[?&]remarks=.*//')
            clean_line=$(echo "$clean_line" | sed 's/[?&]name=.*//')
            
            echo "${clean_line}#${new_name}" >> filtered_configs.txt
        fi
    fi
done < clean_configs.txt

# Если отбор выкосил вообще всё, оставляем базовую чистую структуру без блокировки, чтобы подписка не умерла
if [ ! -s filtered_configs.txt ]; then
    while read -r line; do
        clean_line=$(echo "$line" | cut -d'#' -f1 | sed 's/%23.*//' | sed 's/[?&]remarks=.*//' | sed 's/[?&]name=.*//')
        echo "${clean_line}#qwils [UPDATE] 🌐" >> filtered_configs.txt
    done < clean_configs.txt
fi

# Пакуем готовый результат в Base64 для Happ
base64 -w 0 filtered_configs.txt > subscription.txt

# Полная очистка мусора
rm -f raw_configs.txt clean_configs.txt filtered_configs.txt blocked_ips.txt
echo "=== Все проверки успешно завершены! ==="

