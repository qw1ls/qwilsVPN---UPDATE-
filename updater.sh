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

# ТОТАЛЬНЫЙ СРЕЗ: Берем только выносливые протоколы. Хистерии и Vmess банятся сразу!
grep -oE '(vless|ss|trojan)://[^"& ]+' raw_configs.txt | sort -u > clean_configs.txt
total_servers=$(wc -l < clean_configs.txt)
echo "Скачано потенциальных нод: $total_servers"

echo "=== Старт УСИЛЕННОЙ многопоточной TCP-проверки ==="
THREAD_LIMIT=60
count=0

urldecode() { : "${*//+/ }"; echo -e "${_//%/\\x}"; }

while read -r line; do
    # Извлекаем домен/IP и порт
    server_host=$(echo "$line" | grep -oE '@[^:]+' | tr -d '@' | head -n 1)
    server_port=$(echo "$line" | grep -oE ':[0-9]+' | tr -d ':' | head -n 1)
    
    if [ ! -z "$server_host" ] && [ ! -z "$server_port" ]; then
        {
            # Усиленный тройной тест: сокет должен ответить строго в течение 1.5 секунд
            if curl -s --connect-timeout 1.5 "telnet://${server_host}:${server_port}" > /dev/null 2>&1 || \
               curl -s --connect-timeout 1.5 "https://${server_host}:${server_port}" > /dev/null 2>&1; then
                
                # Сервер реально живой и ответил на запрос! Парсим страну
                decoded_line=$(urldecode "$line")
                flag=$(echo "$decoded_line" | grep -oP '[\x{1F1E6}-\x{1F1FF}]{2}' 2>/dev/null | head -n 1)

                if [ -z "$flag" ]; then
                    if echo "$decoded_line" | grep -riqE '(netherlands|holland|\bNL\b)'; then flag="🇳🇱"
                    elif echo "$decoded_line" | grep -riqE '(united states|america|\bUS\b|\bUSA\b)'; then flag="🇺🇸"
                    elif echo "$decoded_line" | grep -riqE '(germany|nuremberg|\bDE\b)'; then flag="🇩🇪"
                    elif echo "$decoded_line" | grep -riqE '(finland|\bFI\b)'; then flag="🇫🇮"
                    elif echo "$decoded_line" | grep -riqE '(france|roubaix|\bFR\b)'; then flag="🇫🇷"
                    elif echo "$decoded_line" | grep -riqE '(sweden|\bSE\b)'; then flag="🇸🇪"
                    elif echo "$decoded_line" | grep -riqE '(poland|warsaw|wroclaw|\bPL\b)'; then flag="🇵🇱"
                    elif echo "$decoded_line" | grep -riqE '(kazakhstan|\bKZ\b)'; then flag="🇰🇿"
                    elif echo "$decoded_line" | grep -riqE '(japan|\bJP\b)'; then flag="🇯🇵"
                    elif echo "$decoded_line" | grep -riqE '(korea|\bKR\b)'; then flag="🇰🇷"
                    elif echo "$decoded_line" | grep -riqE '(singapore|\bSG\b)'; then flag="🇸🇬"
                    elif echo "$decoded_line" | grep -riqE '(turkey|\bTR\b)'; then flag="🇹🇷"
                    elif echo "$decoded_line" | grep -riqE '(hong kong|\bHK\b)'; then flag="🇭🇰"
                    elif echo "$decoded_line" | grep -riqE '(united arab|emirates|\bAE\b)'; then flag="🇦🇪"
                    elif echo "$decoded_line" | grep -riqE '(united kingdom|london|manchester|\bUK\b|\bGB\b)'; then flag="🇬🇧"
                    elif echo "$decoded_line" | grep -riqE '(latvia|\bLV\b)'; then flag="🇱🇻"
                    elif echo "$decoded_line" | grep -riqE '(estonia|\bEE\b)'; then flag="🇪🇪"
                    elif echo "$decoded_line" | grep -riqE '(austria|\bAT\b)'; then flag="🇦🇹"
                    elif echo "$decoded_line" | grep -riqE '(switzerland|\bCH\b)'; then flag="🇨🇭"
                    elif echo "$decoded_line" | grep -riqE '(canada|\bCA\b)'; then flag="🇨🇦"
                    elif echo "$decoded_line" | grep -riqE '(italy|\bIT\b)'; then flag="🇮🇹"
                    elif echo "$decoded_line" | grep -riqE '(ukraine|\bUA\b)'; then flag="🇺🇦"
                    else flag="🌐"
                    fi
                fi

                # Чистим строку и пишем новое имя
                new_name="qwils [UPDATE] ${flag}"
                clean_line=$(echo "$line" | cut -d'#' -f1 | sed 's/%23.*//' | sed 's/[?&]remarks=.*//' | sed 's/[?&]name=.*//')
                
                echo "${clean_line}#${new_name}" >> filtered_configs.txt
            fi
        } &
        
        ((count++))
        if (( count % THREAD_LIMIT == 0 )); then
            wait
        fi
    fi
done < clean_configs.txt
wait

# Страховочный список на случай, если супер-фильтр снес абсолютно всё
if [ ! -s filtered_configs.txt ]; then
    while read -r line; do
        clean_line=$(echo "$line" | cut -d'#' -f1 | sed 's/%23.*//' | sed 's/[?&]remarks=.*//' | sed 's/[?&]name=.*//')
        echo "${clean_line}#qwils [UPDATE] 🌐" >> filtered_configs.txt
    done < clean_configs.txt
fi

# Конвертируем в Base64 для Happ
base64 -w 0 filtered_configs.txt > subscription.txt

# Стираем мусор
rm -f raw_configs.txt clean_configs.txt filtered_configs.txt
echo "=== Ультра-проверка успешно завершена! ==="

