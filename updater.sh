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

# ТОТАЛЬНЫЙ СРЕЗ: Вырезаем только выносливые vless, ss и trojan
grep -oE '(vless|ss|trojan)://[^"& ]+' raw_configs.txt | sort -u > clean_configs.txt
total_servers=$(wc -l < clean_configs.txt)
echo "Успешно скачано потенциальных нод: $total_servers"

echo "=== Старт УЛЬТРА-БЫСТРОЙ TCP-проверки и расстановки флагов ==="
export -f echo

# Функция проверки отдельной строки (работает внутри xargs)
check_line() {
    local line="$1"
    local server_host=$(echo "$line" | grep -oE '@[^:]+' | tr -d '@' | head -n 1)
    local server_port=$(echo "$line" | grep -oE ':[0-9]+' | tr -d ':' | head -n 1)
    
    if [ ! -z "$server_host" ] && [ ! -z "$server_port" ]; then
        # Ставим жесткий таймаут 1 секунду: если сервер живой, он ответит мгновенно
        if curl -s --connect-timeout 1 "telnet://${server_host}:${server_port}" > /dev/null 2>&1 || \
           curl -s --connect-timeout 1 "https://${server_host}:${server_port}" > /dev/null 2>&1; then
            
            # Быстро декодируем URL-символы флагов
            local decoded=$(echo -e "${line//%/\\x}")
            local flag=$(echo "$decoded" | grep -oP '[\x{1F1E6}-\x{1F1FF}]{2}' 2>/dev/null | head -n 1)

            if [ -z "$flag" ]; then
                if echo "$decoded" | grep -riqE '(netherlands|holland|\bNL\b)'; then flag="🇳🇱"
                elif echo "$decoded" | grep -riqE '(united states|america|\bUS\b|\bUSA\b)'; then flag="🇺🇸"
                elif echo "$decoded" | grep -riqE '(germany|nuremberg|\bDE\b)'; then flag="🇩🇪"
                elif echo "$decoded" | grep -riqE '(finland|\bFI\b)'; then flag="🇫🇮"
                elif echo "$decoded" | grep -riqE '(france|roubaix|\bFR\b)'; then flag="🇫🇷"
                elif echo "$decoded" | grep -riqE '(poland|warsaw|\bPL\b)'; then flag="🇵🇱"
                elif echo "$decoded" | grep -riqE '(kazakhstan|\bKZ\b)'; then flag="🇰🇿"
                elif echo "$decoded" | grep -riqE '(japan|\bJP\b)'; then flag="🇯🇵"
                elif echo "$decoded" | grep -riqE '(united kingdom|london|\bUK\b)'; then flag="🇬🇧"
                elif echo "$decoded" | grep -riqE '(spain|\bES\b)'; then flag="🇪🇸"
                elif echo "$decoded" | grep -riqE '(italy|\bIT\b)'; then flag="🇮🇹"
                else flag="🌐"
                fi
            fi

            # Чистим итоговую строку от мусора
            local clean_line=$(echo "$line" | cut -d'#' -f1 | sed 's/%23.*//' | sed 's/[?&]remarks=.*//' | sed 's/[?&]name=.*//')
            echo "${clean_line}#qwils [UPDATE] ${flag}" >> filtered_configs.txt
        fi
    fi
}
export -f check_line

# Запускаем бешеную параллельную обработку в 150 потоков через xargs
xargs -P 150 -I {} bash -c 'check_line "{}"' < clean_configs.txt

# Страховочный список
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

