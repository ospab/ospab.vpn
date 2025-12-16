#!/usr/bin/env python3
"""ospab.vpn - Lightweight GUI wrapper based on client.py"""
import asyncio
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import client as core

PROXY_PORT = core.PROXY_PORT


class GUIApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('ospab.vpn - GUI')
        self.root.geometry('560x520')
        self.root.resizable(False, False)

        self.loop = None
        self.loop_thread = None
        self.server_obj = None

        self._setup_widgets()
        # redirect core.log to GUI
        core.log = lambda msg: self.append_log(str(msg))

    def _setup_widgets(self):
        header = tk.Frame(self.root, bg='#2d3436', height=70)
        header.pack(fill='x')
        header.pack_propagate(False)
        tk.Label(header, text='🔐 ospab.vpn', font=('Segoe UI', 18, 'bold'), fg='white', bg='#2d3436').pack(pady=(10, 0))

        cfg = tk.LabelFrame(self.root, text=' Configuration ', padx=10, pady=8)
        cfg.pack(fill='x', padx=12, pady=8)

        self.fields = {}
        for i, (label, default) in enumerate([('Server IP', core.SERVER), ('Port', str(core.PORT)), ('UUID', core.UUID), ('SNI', core.SNI)]):
            tk.Label(cfg, text=label + ':').grid(row=i, column=0, sticky='w', pady=4)
            var = tk.StringVar(value=default)
            entry = ttk.Entry(cfg, textvariable=var, width=44)
            entry.grid(row=i, column=1, pady=4, padx=6)
            # Bind paste (Ctrl+V, Command+V, Shift-Insert)
            entry.bind('<Control-v>', lambda e: e.widget.event_generate('<<Paste>>'))
            entry.bind('<Control-V>', lambda e: e.widget.event_generate('<<Paste>>'))
            entry.bind('<Command-v>', lambda e: e.widget.event_generate('<<Paste>>'))
            entry.bind('<Shift-Insert>', lambda e: e.widget.event_generate('<<Paste>>'))
            # right-click menu
            menu = tk.Menu(entry, tearoff=0)
            menu.add_command(label='Paste', command=lambda w=entry: w.event_generate('<<Paste>>'))
            entry.bind('<Button-3>', lambda e, m=menu: m.tk_popup(e.x_root, e.y_root))
            self.fields[label] = var

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(fill='x', padx=12)

        self.status_var = tk.StringVar(value='Disconnected')
        ttk.Label(btn_frame, textvariable=self.status_var).pack(side='left')

        self.connect_btn = ttk.Button(btn_frame, text='🚀 Connect', command=self.on_connect)
        self.connect_btn.pack(side='right')

        save_btn = ttk.Button(btn_frame, text='💾 Save', command=self.on_save)
        save_btn.pack(side='right', padx=6)

        # Logs
        self.log_widget = ScrolledText(self.root, height=14, state='disabled')
        self.log_widget.pack(fill='both', expand=True, padx=12, pady=(8, 12))
        self.append_log('Подсказка: Ctrl+V / Command+V / Shift+Insert для вставки')

        self.root.protocol('WM_DELETE_WINDOW', self.on_close)

    def append_log(self, msg: str):
        self.log_widget.configure(state='normal')
        self.log_widget.insert('end', msg + '\n')
        self.log_widget.see('end')
        self.log_widget.configure(state='disabled')

    def _start_loop_thread(self):
        if self.loop and self.loop.is_running():
            return
        def loop_thread():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_forever()
        self.loop_thread = threading.Thread(target=loop_thread, daemon=True)
        self.loop_thread.start()

    def on_save(self):
        core.SERVER = self.fields['Server IP'].get()
        core.PORT = int(self.fields['Port'].get() or core.PORT)
        core.UUID = self.fields['UUID'].get()
        core.SNI = self.fields['SNI'].get() or core.SNI
        core.save_config()
        self.append_log('Config saved to config.yml')

    def on_connect(self):
        if self.connect_btn['text'] != '🛑 Disconnect':
            # start
            server = self.fields['Server IP'].get()
            uuid = self.fields['UUID'].get()
            if not server or not uuid:
                messagebox.showerror('Error', 'Server IP and UUID required')
                return
            core.SERVER = server
            try:
                core.PORT = int(self.fields['Port'].get() or core.PORT)
            except Exception:
                return messagebox.showerror('Error', 'Port must be numeric')
            core.UUID = uuid
            core.SNI = self.fields['SNI'].get() or core.SNI

            self.append_log('Starting client...')
            self._start_loop_thread()
            fut = asyncio.run_coroutine_threadsafe(self._start_client(), self.loop)
            def cb(f):
                try:
                    f.result()
                    self.root.after(0, lambda: self._on_started())
                except Exception as exc:
                    err = str(exc)
                    self.root.after(0, lambda msg=err: self.append_log(f'Connect error: {msg}'))
            fut.add_done_callback(cb)
            self.connect_btn.config(text='⏳ Connecting')
            self.status_var.set('Connecting...')
        else:
            # stop
            self.append_log('Stopping client...')
            fut = asyncio.run_coroutine_threadsafe(self._stop_client(), self.loop)
            def cb_stop(f):
                self.root.after(0, lambda: self._on_stopped())
            fut.add_done_callback(cb_stop)
            self.connect_btn.config(text='Stopping...')
            self.status_var.set('Stopping...')

    async def _start_client(self):
        # test connection first
        ok = await core.test_connection()
        if not ok:
            raise RuntimeError('Test connection failed')
        ok = await core.mux.connect(core.SERVER, core.PORT, core.UUID, core.SNI)
        if not ok:
            raise RuntimeError('Failed to connect to Reality server')
        # start local proxy server
        self.server_obj = await asyncio.start_server(core.proxy_handler, '127.0.0.1', core.PROXY_PORT)
        core.set_proxy(True)
        core.log(f'Proxy listening on 127.0.0.1:{core.PROXY_PORT}')

    async def _stop_client(self):
        try:
            if self.server_obj:
                self.server_obj.close()
                await self.server_obj.wait_closed()
                self.server_obj = None
        except Exception:
            pass
        try:
            core.set_proxy(False)
        except Exception:
            pass
        try:
            core.mux.close()
        except Exception:
            pass

    def _on_started(self):
        self.connect_btn.config(text='🛑 Disconnect')
        self.status_var.set(f'Connected - Proxy 127.0.0.1:{PROXY_PORT}')

    def _on_stopped(self):
        self.connect_btn.config(text='🚀 Connect')
        self.status_var.set('Disconnected')
        self.append_log('Stopped')

    def on_close(self):
        # ensure stop
        if self.connect_btn['text'] == '🛑 Disconnect':
            fut = asyncio.run_coroutine_threadsafe(self._stop_client(), self.loop)
            try:
                fut.result(timeout=3)
            except Exception:
                pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    app = GUIApp()
    # try to pre-load config
    try:
        core.load_config()
        app.fields['Server IP'].set(core.SERVER)
        app.fields['Port'].set(str(core.PORT))
        app.fields['UUID'].set(core.UUID)
        app.fields['SNI'].set(core.SNI)
    except Exception:
        pass
    app.run()


if __name__ == '__main__':
    main()