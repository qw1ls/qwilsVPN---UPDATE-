#!/bin/bash

# Создаем пустой рабочий файл
> raw_configs.txt

# 1. Скачиваем статические источники
curl -sL "https://githubusercontent.com" >> raw_configs.txt
curl -sL "https://githubusercontent.com" >> raw_configs.txt
curl -sL "https://jsdelivr.net" >> raw_configs.txt

# 2. Скачиваем цикл по грибам от 1 до 25
for i in {1..25}; do
    curl -sL "https://githubusercontent.com{i}.txt" >> raw_configs.txt
done

# 3. Фильтруем только чистые протоколы и удаляем дубликаты
grep -oE '(vless|ss|vmess|trojan|hysteria2|hy2)://[^"& ]+' raw_configs.txt | sort -u > clean_configs.txt

# 4. Сразу кодируем весь чистый массив в Base64 для Happ
base64 -w 0 clean_configs.txt > subscription.txt

# Чистим временный мусор
rm raw_configs.txt clean_configs.txt
