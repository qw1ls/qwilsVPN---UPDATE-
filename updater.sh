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
echo "Успешно скачано серверов благодаря маскировке: $total_servers"

echo "=== Старт проверки портов и гео-определения ==="
# Работаем в параллельных потоках, чтобы уложиться в лимиты времени
while read -r line; do
    ((proxy_count=proxy_count%50)); ((proxy_count++==0)) && wait
    
    {
        server_host=$(echo "$line" | grep -oE '@[^:]+' | tr -d '@' | head -n 1)
        server_port=$(echo "$line" | grep -oE ':[0-9]+' | tr -d ':' | head -n 1)
        
        if [ ! -z "$server_host" ] && [ ! -z "$server_port" ]; then
            # Проверяем доступность порта сервера
            if nc -z -w 3 "$server_host" "$server_port" > /dev/null 2>&1; then
                
                # Запрос гео-определения страны
                country_code=$(curl -s --connect-timeout 2 "https://ipapi.co")
                
                if [ -z "$country_code" ] || [ ${#country_code} -gt 3 ]; then
                    country_code="UN"
                else
                    country_code=$(echo "$country_code" | tr '[:lower:]' '[:upper:]')
                fi
                
                # Формат названия: СТРАНА_КОД qwils [UPDATE]
                new_name="${country_code} qwils [UPDATE]"
                
                if [[ "$line" == *#* ]]; then
                    cleaned_line=$(echo "$line" | cut -d'#' -f1)
                    echo "${cleaned_line}#${new_name}" >> filtered_configs.txt
                else
                    echo "${line}#${new_name}" >> filtered_configs.txt
                fi
            fi
        fi
    } &
done < clean_configs.txt
wait

# Если жесткий отбор отсеял всё, сохраняем базовый список с пометкой UN
if [ ! -s filtered_configs.txt ]; then
    while read -r line; do
        if [[ "$line" == *#* ]]; then
            cleaned_line=$(echo "$line" | cut -d'#' -f1)
            echo "${cleaned_line}#UN qwils [UPDATE]" >> filtered_configs.txt
        else
            echo "${line}#UN qwils [UPDATE]" >> filtered_configs.txt
        fi
    done < clean_configs.txt
fi

# Кодируем в Base64 для Happ
base64 -w 0 filtered_configs.txt > subscription.txt

# Полная очистка мусора
rm -f raw_configs.txt clean_configs.txt filtered_configs.txt
echo "=== Успешно завершено! ==="
