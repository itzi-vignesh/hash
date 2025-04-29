import os
import sys
import ctypes
import subprocess
import getpass
import tempfile
import tkinter as tk
from tkinter import ttk
import ttkbootstrap as tb
from ttkbootstrap import Style
from hash_generator import HashGenerator  # Import Hash Generator Class
from hash_comparator import HashComparator  # Import Hash Comparator Class

# Suppress GLib warnings
os.environ['GIO_USE_VFS'] = 'local'
os.environ['GIO_USE_VOLUME_MONITOR'] = 'unix'

if getattr(sys, 'frozen', False):
    base_path = os.path.dirname(sys.executable)
else:
    base_path = os.path.dirname(__file__)

# Set up font configuration
fontconfig_dir = os.path.join(base_path, "fontconfig")
fonts_dir = os.path.join(base_path, "fonts")

# Create directories if they don't exist
os.makedirs(fontconfig_dir, exist_ok=True)
os.makedirs(fonts_dir, exist_ok=True)
os.makedirs(os.path.join(fontconfig_dir, "cache"), exist_ok=True)

# Set font configuration
fontconfig_path = os.path.join(fontconfig_dir, "fonts.conf")
os.environ["FONTCONFIG_FILE"] = fontconfig_path
os.environ["FONTCONFIG_PATH"] = fonts_dir

# Add DLLs folder to PATH
dll_path = os.path.join(os.path.dirname(sys.executable), "dlls")
os.environ["PATH"] += os.pathsep + dll_path

# Set icon path to head.ico
icon_path = os.path.join(base_path, "logo.ico")

# 🟢 Temporary session tracking file to prevent multiple password prompts
SESSION_FILE = os.path.join(tempfile.gettempdir(), "hash_app_admin_session")

def is_session_active():
    """Check if admin session is already active (to avoid multiple prompts)."""
    return os.path.exists(SESSION_FILE)

def activate_session():
    """Activate session so the user isn't asked for admin password multiple times."""
    with open(SESSION_FILE, "w") as f:
        f.write("active")

def clear_session():
    """Clear session file on exit or logout."""
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)

def verify_admin_password():
    """Prompt user for an admin password on Linux/macOS and verify it before requesting privileges."""
    if os.name == "nt":
        return True  # Windows handles UAC natively

    if is_session_active():
        print("✅ Admin session is active. Skipping password prompt.")
        return True

    admin_password = getpass.getpass("🔑 Enter admin password: ")
    try:
        check_cmd = f"echo {admin_password} | sudo -S id -u"
        result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Password verified. Proceeding with admin request...")
            activate_session()
            return True
        else:
            print("❌ Incorrect password! Admin access denied.")
            return False
    except Exception as e:
        print(f"⚠️ Error verifying password: {e}")
        return False

def request_admin():
    """Securely request admin privileges across Windows, Linux, and macOS."""
    if os.name == "nt":  # Windows
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        except AttributeError:
            is_admin = False

        if not is_admin:
            print("🔒 Requesting admin privileges (Windows UAC)...")
            script = sys.executable
            params = f'"{sys.argv[0]}"' + " ".join(f'"{arg}"' for arg in sys.argv[1:])
            try:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", script, params, None, 0)
                sys.exit(0)
            except Exception as e:
                print(f"❌ Admin privilege request failed: {e}")
                sys.exit(1)
    else:  # Linux/macOS
        if os.geteuid() != 0:
            if not verify_admin_password():
                sys.exit(1)
            print("🔒 Requesting admin privileges...")
            try:
                if "darwin" in sys.platform:
                    script = 'do shell script "python3 ' + sys.argv[0] + '" with administrator privileges'
                    subprocess.run(["osascript", "-e", script], check=True)
                else:
                    if subprocess.run(["which", "pkexec"], capture_output=True, text=True).stdout.strip():
                        subprocess.run(["pkexec", sys.executable] + sys.argv, check=True)
                    else:
                        subprocess.run(["sudo", sys.executable] + sys.argv, check=True)
            except subprocess.CalledProcessError:
                print("❌ Admin privilege request denied. Exiting.")
                sys.exit(1)

import atexit
atexit.register(clear_session)

class IntegratedApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SHA-512 Integrity Tool")
        self.root.geometry("800x600")
        self.root.resizable(False, False)

        # Set the custom icon
        if os.path.exists(icon_path):
            try:
                if sys.platform.startswith("win"):
                    self.root.iconbitmap(icon_path)
                else:
                    # For Linux/macOS, use PhotoImage and iconphoto()
                    img = tk.PhotoImage(file=icon_path)
                    self.root.iconphoto(True, img)
            except Exception as e:
                print(f"⚠️ Warning: Could not set application icon: {e}")

        # Apply ttkbootstrap style
        self.style = Style()  # Initialize style first
        available_themes = self.style.theme_names()
        self.light_theme = "flatly" if "flatly" in available_themes else "cosmo"
        self.dark_theme = "superhero" if "superhero" in available_themes else "darkly"
        self.style.theme_use(self.light_theme)  # Default theme

        # Create Notebook (Tabbed Interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both")
        self.style.configure("TNotebook.Tab", padding=[50, 10], font=("Arial", 10, "bold"), anchor="center")

        # Hash Generator Tab
        self.generator_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.generator_frame, text="  🔐 Hash Generator  ")

        # Hash Comparator Tab
        self.comparator_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.comparator_frame, text="  🔍 Hash Comparator  ")

        # Bind function to resize tabs dynamically
        self.root.bind("<Configure>", self.resize_tabs)

        # Initialize the two GUIs inside respective tabs
        self.generator = HashGenerator(self.generator_frame)
        self.comparator = HashComparator(self.comparator_frame)

        # Theme Toggle (Switch-like Button)
        self.theme_var = tk.BooleanVar(value=False)  # False = Light Theme, True = Dark Theme
        self.toggle_switch = ttk.Checkbutton(
            root,
            bootstyle="round-toggle",
            variable=self.theme_var,
            command=self.toggle_theme,
            text="🌙",  # Default emoji for light mode
        )
        self.toggle_switch.place(relx=0.98, rely=0.08, anchor="ne")  # Top-right, just below the notebook

    def resize_tabs(self, event=None):
        """Adjust the tab width dynamically when resizing the window."""
        self.root.update_idletasks()
        tab_count = len(self.notebook.tabs())
        if tab_count > 0:
            new_width = self.root.winfo_width() // tab_count
            self.style.configure("TNotebook.Tab", width=new_width)

    def toggle_theme(self):
        """Toggle between Light (flatly) and Dark (superhero) mode."""
        if self.theme_var.get():
            self.style.theme_use(self.dark_theme)
            self.toggle_switch.config(text="☀️")
        else:
            self.style.theme_use(self.light_theme)
            self.toggle_switch.config(text="🌙")

if __name__ == "__main__":
    request_admin()  # Request admin privileges before launching the GUI
    root = tk.Tk()
    app = IntegratedApp(root)
    root.mainloop()
