#!/bin/bash

# Создаем пустой рабочий файл
> raw_configs.txt

# 1. Скачиваем статические источники (УБЕРИТЕ ПРОБЕЛЫ ВОКРУГ ТОЧЕК!)
curl -sL "https://raw . githubusercontent . com/0xRadikal/Free-v2ray-Configs/refs/heads/main/all/configs.txt" >> raw_configs.txt
curl -sL "https://raw . githubusercontent . com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt" >> raw_configs.txt
curl -sL "https://fastly . jsdelivr . net/gh/whoahaow/rjsxrd@main/githubmirror/bypass/bypass-all.txt" >> raw_configs.txt

# 2. Скачиваем цикл по грибам от 1 до 25
for i in {1..25}; do
    curl -sL "https://raw . githubusercontent . com/hiztin/VLESS-PO-GRIBI/main/deploy/subscriptions/${i}.txt" >> raw_configs.txt
done

# 3. Фильтруем чистые протоколы и убираем дубликаты
grep -oE '(vless|ss|vmess|trojan|hysteria2|hy2)://[^"& ]+' raw_configs.txt | sort -u > clean_configs.txt

# 4. Проверка серверов (Быстрый пинг)
> filtered_configs.txt
while read -r line; do
    # Извлекаем IP/домен сервера из ссылки
    server=$(echo "$line" | grep -oE '@[^:]+' | tr -d '@')
    if [ ! -z "$server" ]; then
        # Проверяем узел быстрым пингом (таймаут 2 секунды). Если узел живой, заносим в белый список
        if ping -c 1 -W 2 "$server" > /dev/null 2>&1; then
            echo "$line" >> filtered_configs.txt
        fi
    fi
done < clean_configs.txt

# Если проверка по какой-то причине отсеяла вообще всё, оставляем исходный чистый список, чтобы не сломать подписку
if [ ! -s filtered_configs.txt ]; then
    cat clean_configs.txt > filtered_configs.txt
fi

# 5. Кодируем итоговый рабочий список в формат Base64 подписки
base64 -w 0 filtered_configs.txt > subscription.txt

# Чистим временные файлы
rm raw_configs.txt clean_configs.txt filtered_configs.txt
