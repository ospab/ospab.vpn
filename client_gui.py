# vless_reality_client_gui.py
# GUI версия VLESS-Reality клиента для олимпиады

import asyncio
import random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from datetime import datetime
import sys

# --- Configuration (Configuration) ---
SERVER_IP = '127.0.0.1'
SERVER_PORT = 4433
REALITY_SNI = "www.microsoft.com"
VLESS_UUID = None  # Будет запрошен у пользователя
VLESS_MAGIC_HEADER = b'\x56\x4c\x45\x53'
CHUNK_SIZE = 50
KEEP_ALIVE_INTERVAL = 60  # seconds

class VLESSClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VLESS-Reality VPN Client")
        self.root.geometry("700x600")
        self.root.resizable(False, False)
        
        # Стиль
        style = ttk.Style()
        style.theme_use('clam')
        
        # Переменные состояния
        self.connected = False
        self.reader = None
        self.writer = None
        self.loop = None
        self.keep_alive_task = None
        
        self._create_widgets()
        
    def _create_widgets(self):
        # --- Header ---
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)
        
        title_label = tk.Label(
            header_frame,
            text="VLESS-Reality VPN Client",
            font=("Arial", 18, "bold"),
            bg="#2c3e50",
            fg="white"
        )
        title_label.pack(pady=10)
        
        subtitle_label = tk.Label(
            header_frame,
            text="Муниципальный этап олимпиады по ИБ",
            font=("Arial", 10),
            bg="#2c3e50",
            fg="#ecf0f1"
        )
        subtitle_label.pack()
        
        # --- Connection Info ---
        info_frame = tk.LabelFrame(
            self.root,
            text="Настройки подключения",
            font=("Arial", 10, "bold"),
            padx=15,
            pady=10
        )
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # UUID Input
        tk.Label(info_frame, text="UUID:", font=("Arial", 9)).grid(row=0, column=0, sticky=tk.W, pady=2)
        self.uuid_entry = tk.Entry(info_frame, font=("Arial", 9), width=40)
        self.uuid_entry.grid(row=0, column=1, columnspan=2, sticky=tk.W, pady=2, padx=(5, 0))
        
        # Server
        tk.Label(info_frame, text="Сервер:", font=("Arial", 9)).grid(row=1, column=0, sticky=tk.W, pady=2)
        self.server_entry = tk.Entry(info_frame, font=("Arial", 9), width=20)
        self.server_entry.insert(0, f"{SERVER_IP}:{SERVER_PORT}")
        self.server_entry.grid(row=1, column=1, sticky=tk.W, pady=2, padx=(5, 0))
        
        # SNI
        tk.Label(info_frame, text="Reality SNI:", font=("Arial", 9)).grid(row=2, column=0, sticky=tk.W, pady=2)
        tk.Label(info_frame, text=REALITY_SNI, font=("Arial", 9, "bold")).grid(row=2, column=1, sticky=tk.W, pady=2, padx=(5, 0))
        
        # Status
        tk.Label(info_frame, text="Статус:", font=("Arial", 9)).grid(row=1, column=2, sticky=tk.W, padx=(20, 0), pady=2)
        self.status_label = tk.Label(
            info_frame,
            text="Не подключен",
            font=("Arial", 9, "bold"),
            fg="red"
        )
        self.status_label.grid(row=1, column=3, sticky=tk.W, pady=2)
        
        # --- Log Window ---
        log_frame = tk.LabelFrame(
            self.root,
            text="Журнал событий",
            font=("Arial", 10, "bold"),
            padx=10,
            pady=10
        )
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=15,
            font=("Consolas", 9),
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # --- Message Input ---
        input_frame = tk.Frame(self.root, padx=10, pady=5)
        input_frame.pack(fill=tk.X, padx=10, pady=(0, 5))
        
        tk.Label(input_frame, text="Сообщение:", font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=(0, 5))
        
        self.message_entry = tk.Entry(input_frame, font=("Arial", 10))
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        self.send_button = tk.Button(
            input_frame,
            text="Отправить",
            font=("Arial", 9, "bold"),
            bg="#27ae60",
            fg="white",
            command=self.send_message,
            width=12,
            state=tk.DISABLED
        )
        self.send_button.pack(side=tk.LEFT)
        
        # --- Control Buttons ---
        button_frame = tk.Frame(self.root, padx=10, pady=5)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        self.connect_button = tk.Button(
            button_frame,
            text="Подключиться",
            font=("Arial", 10, "bold"),
            bg="#3498db",
            fg="white",
            command=self.connect,
            width=15
        )
        self.connect_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.disconnect_button = tk.Button(
            button_frame,
            text="Отключиться",
            font=("Arial", 10, "bold"),
            bg="#e74c3c",
            fg="white",
            command=self.disconnect,
            width=15,
            state=tk.DISABLED
        )
        self.disconnect_button.pack(side=tk.LEFT, padx=(0, 5))
        
        tk.Button(
            button_frame,
            text="Очистить лог",
            font=("Arial", 10),
            bg="#95a5a6",
            fg="white",
            command=self.clear_log,
            width=12
        ).pack(side=tk.RIGHT)
        
    def log(self, message, level="INFO"):
        """Добавить сообщение в лог"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": "#61afef",
            "SUCCESS": "#98c379",
            "ERROR": "#e06c75",
            "SEND": "#e5c07b",
            "RECEIVE": "#c678dd"
        }
        
        self.log_text.insert(tk.END, f"[{timestamp}] ", "time")
        self.log_text.insert(tk.END, f"[{level}] ", level)
        self.log_text.insert(tk.END, f"{message}\n")
        
        # Применить цвета
        self.log_text.tag_config("time", foreground="#7f8c8d")
        self.log_text.tag_config(level, foreground=colors.get(level, "#d4d4d4"))
        
        self.log_text.see(tk.END)
        self.root.update()
        
    def clear_log(self):
        """Очистить лог"""
        self.log_text.delete(1.0, tk.END)
        
    def generate_reality_payload(self):
        """Генерация Reality payload с magic header"""
        tls_header = b'\x16\x03\x01\x00\xfa'
        client_hello_part = f"GET / HTTP/1.1\r\nHost: {REALITY_SNI}\r\n\r\n".encode('utf-8')
        
        insertion_point = random.randint(10, len(client_hello_part) - 5)
        
        reality_payload = (
            tls_header + 
            client_hello_part[:insertion_point] + 
            VLESS_MAGIC_HEADER + 
            client_hello_part[insertion_point:] +
            b'padding_to_match_target_size'
        )
        
        return reality_payload
        
    def connect(self):
        """Подключение к серверу"""
        # Получить UUID от пользователя
        uuid_input = self.uuid_entry.get().strip()
        if not uuid_input:
            messagebox.showerror("Ошибка", "Введите UUID, скопированный с сервера!")
            return
        
        global VLESS_UUID, SERVER_IP, SERVER_PORT
        VLESS_UUID = uuid_input
        
        # Получить сервер:порт
        server_input = self.server_entry.get().strip()
        if ':' in server_input:
            try:
                SERVER_IP, port_str = server_input.split(':', 1)
                SERVER_PORT = int(port_str)
            except ValueError:
                messagebox.showerror("Ошибка", "Неверный формат сервера! Используйте IP:PORT")
                return
        
        self.log("Инициализация подключения...", "INFO")
        self.connect_button.config(state=tk.DISABLED)
        
        # Запуск в отдельном потоке
        thread = threading.Thread(target=self._connect_async, daemon=True)
        thread.start()
        
    def _connect_async(self):
        """Асинхронное подключение"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        try:
            self.loop.run_until_complete(self._do_connect())
        except Exception as e:
            self.log(f"Ошибка подключения: {e}", "ERROR")
            self.root.after(0, self._reset_connection_ui)
            
    async def _do_connect(self):
        """Выполнить подключение"""
        try:
            # Подключение
            self.log(f"Подключение к {SERVER_IP}:{SERVER_PORT}...", "INFO")
            self.reader, self.writer = await asyncio.open_connection(SERVER_IP, SERVER_PORT)
            
            # Reality handshake
            self.log("Отправка Reality handshake...", "SEND")
            reality_payload = self.generate_reality_payload()
            self.writer.write(reality_payload)
            await self.writer.drain()
            
            self.log(f"Reality payload отправлен ({len(reality_payload)} bytes)", "SUCCESS")
            
            # Отправка тестового сообщения
            test_msg = "VLESS_COMMAND_CONNECT_TO_DEST: Initial handshake from GUI client"
            vless_data = test_msg.encode('utf-8')
            
            self.log("Отправка данных чанками...", "SEND")
            for i in range(0, len(vless_data), CHUNK_SIZE):
                chunk = vless_data[i:i + CHUNK_SIZE]
                self.writer.write(chunk)
                await self.writer.drain()
                await asyncio.sleep(random.uniform(0.01, 0.05))
            
            # Получение ответа
            response = await asyncio.wait_for(self.reader.read(4096), timeout=10.0)
            
            if response:
                self.log(f"Получен ответ от сервера: {response.decode('utf-8', errors='ignore')}", "RECEIVE")
                self.log("Подключение успешно установлено!", "SUCCESS")
                self.log("Теперь можно отправлять сообщения для проверки соединения", "INFO")
                
                self.connected = True
                
                # Запуск keep-alive задачи
                self.keep_alive_task = asyncio.create_task(self._keep_alive_loop())
                
                self.root.after(0, self._update_connected_ui)
            else:
                self.log("Сервер не ответил (возможно, Decoy response)", "ERROR")
                self.root.after(0, self._reset_connection_ui)
                
        except asyncio.TimeoutError:
            self.log("Таймаут ожидания ответа от сервера", "ERROR")
            self.root.after(0, self._reset_connection_ui)
        except ConnectionRefusedError:
            self.log(f"Соединение отклонено. Сервер не запущен на {SERVER_IP}:{SERVER_PORT}?", "ERROR")
            self.root.after(0, self._reset_connection_ui)
        except Exception as e:
            self.log(f"Ошибка: {e}", "ERROR")
            self.root.after(0, self._reset_connection_ui)
            
    def _update_connected_ui(self):
        """Обновить UI после подключения"""
        self.status_label.config(text="Подключен", fg="green")
        self.connect_button.config(state=tk.DISABLED)
        self.disconnect_button.config(state=tk.NORMAL)
        self.send_button.config(state=tk.NORMAL)
        self.message_entry.focus()
        
    def _reset_connection_ui(self):
        """Сбросить UI после отключения"""
        self.status_label.config(text="Не подключен", fg="red")
        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)
        self.send_button.config(state=tk.DISABLED)
        self.connected = False
        
    def send_message(self):
        """Отправить сообщение"""
        message = self.message_entry.get().strip()
        if not message:
            return
            
        if not self.connected:
            messagebox.showwarning("Предупреждение", "Нет подключения к серверу!")
            return
            
        self.message_entry.delete(0, tk.END)
        self.send_button.config(state=tk.DISABLED)
        
        # Отправка в отдельном потоке
        thread = threading.Thread(target=self._send_message_async, args=(message,), daemon=True)
        thread.start()
        
    def _send_message_async(self, message):
        """Асинхронная отправка сообщения"""
        try:
            asyncio.run_coroutine_threadsafe(self._do_send(message), self.loop)
        except Exception as e:
            self.log(f"Ошибка отправки: {e}", "ERROR")
            self.root.after(0, lambda: self.send_button.config(state=tk.NORMAL))
            
    async def _do_send(self, message):
        """Выполнить отправку"""
        try:
            self.log(f">>> Отправка сообщения: {message}", "SEND")
            
            data = f"USER_MESSAGE: {message}".encode('utf-8')
            
            # Отправка чанками
            for i in range(0, len(data), CHUNK_SIZE):
                chunk = data[i:i + CHUNK_SIZE]
                self.writer.write(chunk)
                await self.writer.drain()
                await asyncio.sleep(random.uniform(0.01, 0.05))
            
            self.log(f"Отправлено {len(data)} байт", "INFO")
            
            # Получение ответа
            response = await asyncio.wait_for(self.reader.read(4096), timeout=10.0)
            
            if response:
                response_text = response.decode('utf-8', errors='ignore')
                self.log(f"<<< Получен ответ от сервера: {response_text}", "RECEIVE")
            else:
                self.log("Соединение потеряно", "ERROR")
                self.connected = False
                self.root.after(0, self._reset_connection_ui)
                
        except asyncio.TimeoutError:
            self.log("Таймаут ответа", "ERROR")
        except Exception as e:
            self.log(f"Ошибка: {e}", "ERROR")
            self.connected = False
            self.root.after(0, self._reset_connection_ui)
        finally:
            self.root.after(0, lambda: self.send_button.config(state=tk.NORMAL))
            
    async def _keep_alive_loop(self):
        """Периодическая отправка keep-alive PING пакетов"""
        try:
            while self.connected:
                await asyncio.sleep(KEEP_ALIVE_INTERVAL)
                
                if not self.connected:
                    break
                
                try:
                    self.log("Отправка keep-alive PING...", "INFO")
                    # Обновить статус на "Проверка соединения..."
                    self.root.after(0, lambda: self.status_label.config(text="Проверка...", fg="orange"))
                    
                    self.writer.write(b'PING')
                    await self.writer.drain()
                    
                    # Ожидаем PONG
                    pong = await asyncio.wait_for(self.reader.read(4096), timeout=10.0)
                    if pong == b'PONG':
                        self.log("Keep-alive PONG получен", "SUCCESS")
                        # Вернуть статус "Подключен"
                        self.root.after(0, lambda: self.status_label.config(text="Подключен", fg="green"))
                    elif pong == b'SERVER_PING':
                        self.log("Server PING получен, отправка PONG", "INFO")
                        self.writer.write(b'PONG')
                        await self.writer.drain()
                        self.root.after(0, lambda: self.status_label.config(text="Подключен", fg="green"))
                except asyncio.TimeoutError:
                    self.log("Keep-alive timeout - соединение потеряно", "ERROR")
                    self.connected = False
                    self.root.after(0, self._reset_connection_ui)
                    break
        except Exception as e:
            self.log(f"Keep-alive ошибка: {e}", "ERROR")
    
    def disconnect(self):
        """Отключиться от сервера"""
        self.log("Отключение от сервера...", "INFO")
        
        # Отменить keep-alive задачу
        if self.keep_alive_task and not self.keep_alive_task.done():
            self.keep_alive_task.cancel()
        
        if self.writer and not self.writer.is_closing():
            try:
                self.writer.close()
                if self.loop:
                    asyncio.run_coroutine_threadsafe(self.writer.wait_closed(), self.loop)
            except Exception as e:
                self.log(f"Ошибка при закрытии: {e}", "ERROR")
        
        self.connected = False
        self._reset_connection_ui()
        self.log("Отключено", "SUCCESS")
        
    def on_closing(self):
        """Обработка закрытия окна"""
        if self.connected:
            if messagebox.askokcancel("Выход", "Вы подключены. Отключиться и выйти?"):
                self.disconnect()
                self.root.destroy()
        else:
            self.root.destroy()

def main():
    root = tk.Tk()
    app = VLESSClientGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Начальное сообщение
    app.log("VLESS-Reality Client GUI инициализирован", "SUCCESS")
    app.log(f"Готов к подключению к {SERVER_IP}:{SERVER_PORT}", "INFO")
    app.log(f"Reality SNI: {REALITY_SNI}", "INFO")
    
    root.mainloop()

if __name__ == "__main__":
    main()
