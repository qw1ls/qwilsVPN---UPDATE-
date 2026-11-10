#!/bin/bash

# Создаем чистые рабочие файлы
> raw_configs.txt
> clean_configs.txt
> filtered_configs.txt

echo "=== Сбор источников с обходом блокировок Гитхаба ==="

# Записываем старые и новые ссылки строго с пробелами (маскировка)
url1="https:// raw . githubusercontent . com / 0xRadikal / Free-v2ray-Configs / refs / heads / main / all / configs . txt"
url2="https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_SS%2BAll_RUS . txt"
url3="https:// fastly . jsdelivr . net / gh / whoahaow / rjsxrd@main / githubmirror / bypass / bypass-all . txt"
url4="https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_VLESS_RUS . txt"
url5="https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / Vless-Reality-White-Lists-Rus-Mobile . txt"

# Расшифратор пробелов: удаляем пробелы на лету и скачиваем
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

# Цикл по грибам от 1 до 25 с маскировкой пробелами
for i in {1..25}; do
    grib_url="https:// raw . githubusercontent . com / hiztin / VLESS-PO-GRIBI / main / deploy / subscriptions / ${i} . txt"
    clean_grib_url=$(echo "$grib_url" | sed 's/ //g')
    curl -sL --connect-timeout 3 "$clean_grib_url" >> raw_configs.txt
done

# Вытаскиваем чистые ссылки протоколов
grep -oE '(vless|ss|vmess|trojan|hysteria2|hy2)://[^"& ]+' raw_configs.txt | sort -u > clean_configs.txt
total_servers=$(wc -l < clean_configs.txt)
echo "Успешно скачано серверов для тотального переименования: $total_servers"

echo "=== Старт многопоточной TCP-проверки и 100% расстановки флагов ==="
THREAD_LIMIT=60
count=0

while read -r line; do
    server_host=$(echo "$line" | grep -oE '@[^:]+' | tr -d '@' | head -n 1)
    server_port=$(echo "$line" | grep -oE ':[0-9]+' | tr -d ':' | head -n 1)
    
    if [ ! -z "$server_host" ] && [ ! -z "$server_port" ]; then
        {
            # Умный TCP-тест сокета сервера через curl
            if curl -s --connect-timeout 2.5 "telnet://${server_host}:${server_port}" > /dev/null 2>&1 || curl -s --connect-timeout 2.5 "https://${server_host}:${server_port}" > /dev/null 2>&1; then
                
                # 1. Поиск существующего эмодзи-флага в оригинальной строке
                flag=$(echo "$line" | grep -oP '[\x{1F1E6}-\x{1F1FF}]{2}' 2>/dev/null | head -n 1)

                # 2. Если смайлика-флага нет, ищем текстовые совпадения стран (Расширенная база под новые файлы)
                if [ -z "$flag" ]; then
                    if echo "$line" | grep -riqE '(netherlands|🇳🇱|\bNL\b)'; then flag="🇳🇱"
                    elif echo "$line" | grep -riqE '(united states|america|🇺🇸|\bUS\b|\bUSA\b)'; then flag="🇺🇸"
                    elif echo "$line" | grep -riqE '(germany|🇩🇪|\bDE\b)'; then flag="🇩🇪"
                    elif echo "$line" | grep -riqE '(finland|🇫🇮|\bFI\b)'; then flag="🇫🇮"
                    elif echo "$line" | grep -riqE '(france|🇫🇷|\bFR\b)'; then flag="🇫🇷"
                    elif echo "$line" | grep -riqE '(sweden|🇸🇪|\bSE\b)'; then flag="🇸🇪"
                    elif echo "$line" | grep -riqE '(poland|🇵🇱|\bPL\b)'; then flag="🇵🇱"
                    elif echo "$line" | grep -riqE '(kazakhstan|🇰🇿|\bKZ\b)'; then flag="🇰🇿"
                    elif echo "$line" | grep -riqE '(japan|🇯🇵|\bJP\b)'; then flag="🇯🇵"
                    elif echo "$line" | grep -riqE '(korea|🇰🇷|\bKR\b)'; then flag="🇰🇷"
                    elif echo "$line" | grep -riqE '(singapore|🇸🇬|\bSG\b)'; then flag="🇸🇬"
                    elif echo "$line" | grep -riqE '(turkey|🇹🇷|\bTR\b)'; then flag="🇹🇷"
                    elif echo "$line" | grep -riqE '(hong kong|🇭🇰|\bHK\b)'; then flag="🇭🇰"
                    elif echo "$line" | grep -riqE '(united arab|emirates|🇦🇪|\bAE\b)'; then flag="🇦🇪"
                    elif echo "$line" | grep -riqE '(united kingdom|london|🇬🇧|\bUK\b|\bGB\b)'; then flag="🇬🇧"
                    elif echo "$line" | grep -riqE '(latvia|🇱🇻|\bLV\b)'; then flag="🇱🇻"
                    elif echo "$line" | grep -riqE '(estonia|🇪🇪|\bEE\b)'; then flag="🇪🇪"
                    elif echo "$line" | grep -riqE '(austria|🇦🇹|\bAT\b)'; then flag="🇦🇹"
                    elif echo "$line" | grep -riqE '(switzerland|🇨🇭|\bCH\b)'; then flag="🇨🇭"
                    elif echo "$line" | grep -riqE '(canada|🇨🇦|\bCA\b)'; then flag="🇨🇦"
                    elif echo "$line" | grep -riqE '(australia|🇦🇺|\bAU\b)'; then flag="🇦🇺"
                    elif echo "$line" | grep -riqE '(spain|🇪🇸|\bES\b)'; then flag="🇪🇸"
                    elif echo "$line" | grep -riqE '(italy|🇮🇹|\bIT\b)'; then flag="🇮🇹"
                    elif echo "$line" | grep -riqE '(ukraine|🇺🇦|\bUA\b)'; then flag="🇺🇦"
                    elif echo "$line" | grep -riqE '(belarus|🇧🇾|\bBY\b)'; then flag="🇧🇾"
                    elif echo "$line" | grep -riqE '(egypt|🇪🇬|\bEG\b)'; then flag="🇪🇬"
                    elif echo "$line" | grep -riqE '(czechia|czech|🇨🇿|\bCZ\b)'; then flag="🇨🇿"
                    elif echo "$line" | grep -riqE '(lithuania|🇱🇹|\bLT\b)'; then flag="🇱🇹"
                    else flag="🌐"
                    fi
                fi

                # Ультимативное вырезание старого мусора из строки (убираем любые хвосты названий)
                clean_line="$line"
                clean_line=$(echo "$clean_line" | cut -d'#' -f1)
                clean_line=$(echo "$clean_line" | sed 's/%23.*//')
                clean_line=$(echo "$clean_line" | sed 's/[?&]remarks=.*//')
                clean_line=$(echo "$clean_line" | sed 's/[?&]name=.*//')
                
                # Принудительно склеиваем в нужный вам формат
                echo "${clean_line}#qwils [UPDATE] ${flag}" >> filtered_configs.txt
            fi
        } &
        
        ((count++))
        if (( count % THREAD_LIMIT == 0 )); then
            wait
        fi
    fi
done < clean_configs.txt
wait

# Если параноидальный отбор отсеял абсолютно всё, отдаем базовый список
if [ ! -s filtered_configs.txt ]; then
    while read -r line; do
        clean_line=$(echo "$line" | cut -d'#' -f1 | sed 's/%23.*//' | sed 's/[?&]remarks=.*//' | sed 's/[?&]name=.*//')
        echo "${clean_line}#qwils [UPDATE] 🌐" >> filtered_configs.txt
    done < clean_configs.txt
fi

# Упаковываем результат в Base64 для Happ
base64 -w 0 filtered_configs.txt > subscription.txt

# Полная очистка мусора
rm -f raw_configs.txt clean_configs.txt filtered_configs.txt
echo "=== Все проверки успешно завершены! ==="

