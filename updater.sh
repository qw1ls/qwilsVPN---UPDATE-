#!/bin/bash

# Создаем чистые рабочие файлы
> raw_configs.txt
> clean_configs.txt
> filtered_configs.txt

echo "=== Сбор источников с обходом блокировок Гитхаба ==="

# Записываем ссылки строго с пробелами (маскировка)
url1="https:// raw . githubusercontent . com / 0xRadikal / Free-v2ray-Configs / refs / heads / main / all / configs . txt"
url2="https:// raw . githubusercontent . com / igareck / vpn-configs-for-russia / refs / heads / main / BLACK_SS%2BAll_RUS . txt"
url3="https:// fastly . jsdelivr . net / gh / whoahaow / rjsxrd@main / githubmirror / bypass / bypass-all . txt"

# Расшифратор пробелов: удаляем пробелы на лету и скачиваем
clean_url1=$(echo "$url1" | sed 's/ //g')
clean_url2=$(echo "$url2" | sed 's/ //g')
clean_url3=$(echo "$url3" | sed 's/ //g')

curl -sL --connect-timeout 5 "$clean_url1" >> raw_configs.txt
curl -sL --connect-timeout 5 "$clean_url2" >> raw_configs.txt
curl -sL --connect-timeout 5 "$clean_url3" >> raw_configs.txt

# Цикл по грибам от 1 до 25 с маскировкой пробелами
for i in {1..25}; do
    grib_url="https:// raw . githubusercontent . com / hiztin / VLESS-PO-GRIBI / main / deploy / subscriptions / ${i} . txt"
    clean_grib_url=$(echo "$grib_url" | sed 's/ //g')
    curl -sL --connect-timeout 3 "$clean_grib_url" >> raw_configs.txt
done

# Вытаскиваем чистые ссылки протоколов
grep -oE '(vless|ss|vmess|trojan|hysteria2|hy2)://[^"& ]+' raw_configs.txt | sort -u > clean_configs.txt
total_servers=$(wc -l < clean_configs.txt)
echo "Успешно скачано серверов для переименования: $total_servers"

echo "=== Старт расстановки флагов ==="
while read -r line; do
    # 1. Проверяем, есть ли уже эмодзи-флаг в оригинальной строке
    flag=$(echo "$line" | grep -oP '[\x{1F1E6}-\x{1F1FF}]{2}' 2>/dev/null | head -n 1)

    # 2. Если флага-смайлика нет, ищем текстовые совпадения (строго на английском!)
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
        else flag="🌐"
        fi
    fi

    # Собираем имя
    new_name="qwils [UPDATE] ${flag}"
    
    # Меняем название после знака #
    if [[ "$line" == *#* ]]; then
        cleaned_line=$(echo "$line" | cut -d'#' -f1)
        echo "${cleaned_line}#${new_name}" >> filtered_configs.txt
    else
        echo "${line}#${new_name}" >> filtered_configs.txt
    fi
done < clean_configs.txt

# Упаковываем результат в Base64
base64 -w 0 filtered_configs.txt > subscription.txt

# Полная очистка мусора
rm -f raw_configs.txt clean_configs.txt filtered_configs.txt
echo "=== Все проверки успешно завершены! ==="
