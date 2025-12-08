# 🚀 Production Deployment Guide

## ⚠️ КРИТИЧЕСКИЕ ШАГИ БЕЗОПАСНОСТИ

### 1. Генерация Уникального UUID

**НЕ ИСПОЛЬЗУЙТЕ дефолтный UUID в production!**

```bash
# Linux/Mac
python3 -c "import uuid; print(uuid.uuid4())"

# Windows
python -c "import uuid; print(uuid.uuid4())"
```

**Замените UUID** в `server.py` и `client.py` на сгенерированный:
```python
VLESS_UUID = "ВАШ-НОВЫЙ-UUID-ЗДЕСЬ"
```

### 2. Настройка IP Whitelist

В `server.py` добавьте разрешенные IP клиентов:

```python
# Разрешить только определенные IP
ALLOWED_IPS = ['123.45.67.89', '98.76.54.32']

# Или оставить пустым для всех (НЕ рекомендуется)
ALLOWED_IPS = []
```

### 3. Изменение Порта

**Рекомендуется порт 443** (стандартный HTTPS):

```python
# В server.py
LISTEN_PORT = 443
```

**Linux требует root для портов < 1024**:
```bash
sudo python3 server.py
```

### 4. Firewall Configuration

**Ubuntu/Debian**:
```bash
# Разрешить входящий трафик на порт
sudo ufw allow 443/tcp
sudo ufw enable
```

**CentOS/RHEL**:
```bash
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload
```

**Windows**:
```powershell
# PowerShell (от имени администратора)
New-NetFirewallRule -DisplayName "VLESS-Reality" -Direction Inbound -LocalPort 443 -Protocol TCP -Action Allow
```

### 5. Защита от Сканирования

**Установите rate limiting** в `server.py`:
```python
MAX_FAILED_ATTEMPTS = 5  # Бан после 5 неудачных попыток
BAN_TIME = 3600          # Бан на 1 час
```

Это защитит от:
- Брутфорса UUID
- Port scanning
- DDoS атак

---

## 🌐 Деплой на VPS

### Вариант 1: Облачные Провайдеры

**Рекомендуемые провайдеры**:
- DigitalOcean (от $5/месяц)
- Vultr (от $3.50/месяц)
- AWS Lightsail (от $5/месяц)
- Linode (от $5/месяц)

**Требования**:
- Ubuntu 20.04+ или Debian 11+
- 1 GB RAM (минимум)
- 1 CPU core
- 10 GB SSD

### Вариант 2: VPS Setup

1. **Подключение к серверу**:
```bash
ssh root@YOUR_SERVER_IP
```

2. **Установка зависимостей**:
```bash
apt update
apt install -y python3 python3-pip
```

3. **Загрузка проекта**:
```bash
cd /opt
git clone YOUR_REPO_URL vless-reality
cd vless-reality
```

4. **Редактирование конфигурации**:
```bash
nano server.py
# Измените:
# - VLESS_UUID на новый
# - ALLOWED_IPS на IP ваших клиентов
# - LISTEN_PORT на 443
```

5. **Запуск сервера**:
```bash
sudo python3 server.py
```

### Вариант 3: Systemd Service (автозапуск)

Создайте `/etc/systemd/system/vless-reality.service`:

```ini
[Unit]
Description=VLESS-Reality VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vless-reality
ExecStart=/usr/bin/python3 /opt/vless-reality/server.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Активация**:
```bash
sudo systemctl daemon-reload
sudo systemctl enable vless-reality
sudo systemctl start vless-reality
sudo systemctl status vless-reality
```

---

## 👨‍💻 Настройка Клиента

### На Windows

1. **Отредактировать `client.py`**:
```python
SERVER_IP = 'YOUR_SERVER_IP'  # IP вашего VPS
SERVER_PORT = 443              # Порт сервера
VLESS_UUID = 'ВАШ-НОВЫЙ-UUID'  # Тот же UUID что на сервере
```

2. **Запуск**:
```batch
start_client.bat
```

### На Linux

1. **Отредактировать `client.py`**:
```bash
nano client.py
# Изменить SERVER_IP, SERVER_PORT, VLESS_UUID
```

2. **Запуск**:
```bash
sudo ./start_client.sh
```

---

## 🔒 Дополнительная Безопасность

### 1. SSL/TLS Сертификат

Для максимальной маскировки установите **настоящий SSL сертификат**:

```bash
# Установка certbot
apt install -y certbot

# Получение бесплатного сертификата Let's Encrypt
certbot certonly --standalone -d yourdomain.com
```

### 2. Fail2Ban (защита от брутфорса)

```bash
apt install -y fail2ban

# Создать правило для VLESS-Reality
cat > /etc/fail2ban/filter.d/vless-reality.conf << EOF
[Definition]
failregex = ^\[!\] IP <HOST> banned
ignoreregex =
EOF

# Добавить в jail.local
cat >> /etc/fail2ban/jail.local << EOF
[vless-reality]
enabled = true
port = 443
filter = vless-reality
logpath = /var/log/vless-reality.log
maxretry = 3
bantime = 3600
EOF

systemctl restart fail2ban
```

### 3. Логирование

Добавьте логирование в `server.py`:

```python
import logging

logging.basicConfig(
    filename='/var/log/vless-reality.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Замените print() на logging.info()
```

### 4. Мониторинг

**Проверка статуса**:
```bash
systemctl status vless-reality
```

**Просмотр логов**:
```bash
journalctl -u vless-reality -f
```

**Проверка открытых соединений**:
```bash
ss -tuln | grep 443
```

---

## 🧪 Тестирование После Деплоя

### 1. Проверка с локальной машины

**Windows**:
```batch
test_connection.bat YOUR_SERVER_IP
```

**Linux**:
```bash
./test_connection.sh YOUR_SERVER_IP
```

### 2. Проверка Decoy Response

```bash
curl -v http://YOUR_SERVER_IP:443
# Должно вернуть: HTTP/1.1 404 Not Found
```

### 3. Тест Реального Подключения

1. Запустите клиент с новым SERVER_IP
2. Отправьте тестовое сообщение
3. Проверьте логи сервера

---

## ⚠️ ВАЖНЫЕ ПРЕДУПРЕЖДЕНИЯ

### ❌ НЕ ДЕЛАЙТЕ ЭТО:

1. **НЕ используйте дефолтный UUID** - он публичный!
2. **НЕ открывайте сервер без whitelist** если не нужно
3. **НЕ логируйте UUID** в plaintext логи
4. **НЕ используйте HTTP** для передачи конфиденциальных данных
5. **НЕ деплойте** без rate limiting

### ✅ ОБЯЗАТЕЛЬНО СДЕЛАЙТЕ:

1. ✅ Сгенерируйте **новый UUID** для production
2. ✅ Настройте **firewall** на сервере
3. ✅ Установите **Fail2Ban** для защиты
4. ✅ Настройте **systemd** для автозапуска
5. ✅ Регулярно **обновляйте** систему: `apt update && apt upgrade`

---

## 🔧 Troubleshooting

### Проблема: Connection refused

**Решение**:
1. Проверьте firewall: `sudo ufw status`
2. Проверьте, запущен ли сервер: `systemctl status vless-reality`
3. Проверьте порт: `ss -tuln | grep 443`

### Проблема: IP banned

**Решение**:
```bash
# Перезапустить сервер для сброса ban list
systemctl restart vless-reality
```

### Проблема: Высокая нагрузка

**Решение**:
1. Проверьте логи на DDoS: `journalctl -u vless-reality | grep "banned"`
2. Увеличьте BAN_TIME в конфигурации
3. Уменьшите MAX_FAILED_ATTEMPTS

---

## 📊 Мониторинг Производительности

### CPU и Memory

```bash
# Установка htop
apt install -y htop
htop

# Или используйте top
top -p $(pgrep -f server.py)
```

### Network Traffic

```bash
# Установка iftop
apt install -y iftop
sudo iftop -i eth0
```

### Логи в реальном времени

```bash
tail -f /var/log/vless-reality.log
```

---

## 🎯 Checklist Деплоя

- [ ] Сгенерирован новый UUID
- [ ] UUID заменен в server.py и client.py
- [ ] Настроен ALLOWED_IPS whitelist
- [ ] Изменен порт на 443 (опционально)
- [ ] Настроен firewall (ufw/firewalld)
- [ ] Установлен Fail2Ban
- [ ] Создан systemd service
- [ ] Протестирован decoy response
- [ ] Протестировано подключение клиента
- [ ] Настроено логирование
- [ ] Настроен мониторинг

---

**Готово к продакшну!** 🚀

Если все пункты checklist выполнены - ваш сервер защищен и готов к использованию через интернет.
