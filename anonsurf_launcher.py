#!/usr/bin/env python3
"""
AnonSurf GUI Launcher v3.3
Finestra di avvio con richiesta password e scelta versione GUI
"""

import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import sys

class LauncherApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AnonSurf GUI - Avvio")
        self.root.resizable(False, False)
        
        # Centra la finestra
        window_width = 350
        window_height = 200
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Icona (se disponibile)
        try:
            self.root.iconname("AnonSurf")
        except:
            pass
        
        self.create_widgets()
        
        # Gestisci chiusura finestra
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Focus sul campo password
        self.password_entry.focus_set()
        
        # Bind Enter per avviare
        self.root.bind('<Return>', lambda e: self.start_gui())
        
    def create_widgets(self):
        # Frame principale con padding
        main_frame = tk.Frame(self.root, padx=20, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Titolo
        title_label = tk.Label(
            main_frame, 
            text="🛡️ AnonSurf GUI Control Panel",
            font=("Sans", 14, "bold")
        )
        title_label.pack(pady=(0, 15))
        
        # Frame per password
        pwd_frame = tk.Frame(main_frame)
        pwd_frame.pack(fill=tk.X, pady=5)
        
        pwd_label = tk.Label(pwd_frame, text="Password root:", width=15, anchor="w")
        pwd_label.pack(side=tk.LEFT)
        
        self.password_entry = tk.Entry(pwd_frame, show="●", width=20)
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Checkbox per versione mini
        self.mini_var = tk.BooleanVar(value=False)
        self.mini_check = tk.Checkbutton(
            main_frame,
            text="Avvia versione minimale (finestra compatta)",
            variable=self.mini_var
        )
        self.mini_check.pack(pady=15, anchor="w")
        
        # Frame per pulsanti
        btn_frame = tk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        
        # Pulsante Annulla
        cancel_btn = tk.Button(
            btn_frame,
            text="Annulla",
            width=10,
            command=self.on_close
        )
        cancel_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Pulsante Avvia
        start_btn = tk.Button(
            btn_frame,
            text="Avvia",
            width=10,
            command=self.start_gui,
            bg="#4CAF50",
            fg="white",
            activebackground="#45a049"
        )
        start_btn.pack(side=tk.RIGHT)
        
    def start_gui(self):
        password = self.password_entry.get()
        
        if not password:
            messagebox.showerror("Errore", "Inserisci la password")
            self.password_entry.focus_set()
            return
        
        # Determina quale script avviare
        install_dir = "/opt/anonsurf-gui"
        
        if self.mini_var.get():
            script = os.path.join(install_dir, "anonsurf_gui_mini.py")
        else:
            script = os.path.join(install_dir, "anonsurf_gui.py")
        
        # Verifica che il file esista
        if not os.path.exists(script):
            # Prova nella directory corrente
            script_dir = os.path.dirname(os.path.abspath(__file__))
            if self.mini_var.get():
                script = os.path.join(script_dir, "anonsurf_gui_mini.py")
            else:
                script = os.path.join(script_dir, "anonsurf_gui.py")
        
        if not os.path.exists(script):
            messagebox.showerror("Errore", f"File non trovato:\n{script}")
            return
        
        # Verifica password con sudo -S -v
        try:
            check = subprocess.run(
                ["sudo", "-S", "-v"],
                input=password.encode(),
                capture_output=True,
                timeout=10
            )
            
            if check.returncode != 0:
                messagebox.showerror("Errore", "Password errata")
                self.password_entry.delete(0, tk.END)
                self.password_entry.focus_set()
                return
                
        except subprocess.TimeoutExpired:
            messagebox.showerror("Errore", "Timeout verifica password")
            return
        except Exception as e:
            messagebox.showerror("Errore", f"Errore verifica password:\n{e}")
            return
        
        # Chiudi la finestra del launcher
        self.root.withdraw()
        
        # Determina se usare venv
        venv_python = os.path.join(install_dir, "venv", "bin", "python3")
        if os.path.exists(venv_python):
            python_cmd = venv_python
        else:
            python_cmd = "python3"
        
        # Avvia la GUI con sudo
        try:
            # Usa subprocess.Popen per non bloccare e permettere al launcher di chiudersi
            process = subprocess.Popen(
                f"echo '{password}' | sudo -S {python_cmd} {script}",
                shell=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            
            # Piccola attesa per verificare che sia partito
            import time
            time.sleep(0.5)
            
            if process.poll() is not None and process.returncode != 0:
                self.root.deiconify()
                messagebox.showerror("Errore", "Impossibile avviare la GUI")
                return
                
        except Exception as e:
            self.root.deiconify()
            messagebox.showerror("Errore", f"Errore avvio GUI:\n{e}")
            return
        
        # Chiudi il launcher
        self.root.quit()
        self.root.destroy()
        
    def on_close(self):
        self.root.quit()
        self.root.destroy()
        
    def run(self):
        self.root.mainloop()


def main():
    # Verifica che non siamo già root (non serve il launcher)
    if os.geteuid() == 0:
        # Siamo già root, avvia direttamente la GUI
        install_dir = "/opt/anonsurf-gui"
        script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Cerca prima in /opt, poi nella directory corrente
        for base_dir in [install_dir, script_dir]:
            script = os.path.join(base_dir, "anonsurf_gui.py")
            if os.path.exists(script):
                venv_python = os.path.join(base_dir, "venv", "bin", "python3")
                if os.path.exists(venv_python):
                    os.execv(venv_python, [venv_python, script])
                else:
                    os.execv(sys.executable, [sys.executable, script])
        
        print("Errore: anonsurf_gui.py non trovato")
        sys.exit(1)
    
    # Non siamo root, mostra il launcher
    app = LauncherApp()
    app.run()


if __name__ == "__main__":
    main()
