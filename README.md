# ospab.vpn

Reality VPN — протокол с маскировкой под TLS-трафик легитимного сайта.

## Архитектура

```
┌─────────────┐     TLS ClientHello      ┌─────────────┐     HTTP(S)     ┌────────────┐
│   Client    │ ─────────────────────────▶│   Server    │ ───────────────▶│  Internet  │
│ (client.py) │ ◀─────────────────────────│ (server.py) │ ◀───────────────│            │
└─────────────┘   Encrypted Multiplex     └─────────────┘                 └────────────┘
      │
      │ HTTP Proxy :10808
      ▼
┌─────────────┐
│   Browser   │
└─────────────┘
```

## Запуск

### Сервер
```bash
python server.py <port> <uuid> <sni>
python server.py 443 my-secret-key www.microsoft.com
```

### Клиент (CLI)
```bash
python client.py <server_ip> <port> <uuid> <sni>
python client.py 1.2.3.4 443 my-secret-key www.microsoft.com
```

### Клиент (GUI)
```bash
python client_gui.py
```

## Как это работает

1. **Handshake**: Клиент отправляет настоящий TLS ClientHello с HMAC-аутентификацией в поле `session_id`
2. **Проверка**: Сервер проверяет HMAC — если не совпадает, проксирует на реальный сайт (fallback)
3. **Шифрование**: SHA256-CTR поточный шифр на базе UUID и nonce
4. **Мультиплексинг**: Все соединения через один туннель с frame-протоколом `[4B id][2B len][data]`

## Особенности

- Неотличим от обычного HTTPS-трафика
- Fallback на реальный сервер SNI для неаутентифицированных соединений
- Автоматическая настройка системного прокси (Windows)
- GUI-клиент для Windows

## Файлы

| Файл | Описание |
|------|----------|
| `server.py` | Reality-сервер (~280 строк) |
| `client.py` | CLI-клиент (~270 строк) |
| `client_gui.py` | GUI-клиент Tkinter (~290 строк) |

## Структура протокола

### ClientHello Authentication
```
session_id[32] = nonce[16] + HMAC-SHA256(nonce, derive_key(uuid))[:16]
derive_key(uuid) = SHA256("reality-auth-" + uuid)
```

### Frame Format
```
[4 bytes] stream_id (big-endian)
[2 bytes] length (big-endian)
[N bytes] encrypted payload
```

### Cipher (SHA256-CTR)
```
block[i] = SHA256(key + nonce + counter)
ciphertext = plaintext XOR keystream
```
