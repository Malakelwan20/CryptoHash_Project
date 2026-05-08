"""
CryptoHash Analyzer - Student Lab UI Version
Run with: python main.py

This project demonstrates hashing, simple educational encryption,
HMAC, hash verification, and file hashing using Python built-in libraries.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import tkinter as tk
from collections import Counter
from tkinter import filedialog, messagebox

APP_TITLE = "CryptoHash Analyzer"
APP_W = 1220
APP_H = 780

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

# A calm student-lab / notebook theme. Clean, but not too corporate.
BG = "#e7dfd1"
PAPER = "#f7f0e4"
PAPER_2 = "#eadfca"
INK = "#20283a"
MUTED = "#625a50"
LINE = "#c0af96"
NAV = "#26304a"
NAV_2 = "#33405f"
TEAL = "#2f7875"
TEAL_DARK = "#215856"
AMBER = "#c9852d"
ROSE = "#b95763"
GREEN = "#4a8653"
BLUE = "#3f6b98"
PURPLE = "#725997"
INPUT = "#fffaf1"
WHITE = "#ffffff"

HASH_ALGORITHMS = ["MD5", "SHA-1", "SHA-256", "SHA-512", "SHA3-256", "SHA3-512"]
HMAC_ALGORITHMS = ["HMAC-SHA256", "HMAC-SHA512", "HMAC-SHA3-256"]
ENCRYPTION_METHODS = [
    "Caesar Cipher",
    "Vigenere Cipher",
    "XOR Cipher",
    "ROT13",
    "Reverse Text",
    "Base64 Encode",
]


def ensure_user_file():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump([], f, indent=4)


def load_users():
    ensure_user_file()
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_users(users):
    ensure_user_file()
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=4)


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
    ).hex()
    return salt, password_hash


def verify_password(password, salt, expected_hash):
    _, current_hash = hash_password(password, salt)
    return hmac.compare_digest(current_hash, expected_hash)


def get_hash_function(name):
    return {
        "MD5": hashlib.md5,
        "SHA-1": hashlib.sha1,
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "SHA3-256": hashlib.sha3_256,
        "SHA3-512": hashlib.sha3_512,
    }.get(name)


def generate_hash(text, algorithm):
    func = get_hash_function(algorithm)
    if func is None:
        raise ValueError("Invalid hash algorithm")
    return func(text.encode("utf-8")).hexdigest()


def caesar_cipher(text, shift):
    result = []
    for ch in text:
        if ch.isupper():
            result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        elif ch.islower():
            result.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        else:
            result.append(ch)
    return "".join(result)


def vigenere_cipher(text, key):
    clean_key = "".join(ch.lower() for ch in key if ch.isalpha())
    if not clean_key:
        raise ValueError("Vigenere key must contain letters")

    result = []
    key_index = 0
    for ch in text:
        if ch.isalpha():
            shift = ord(clean_key[key_index % len(clean_key)]) - ord("a")
            if ch.isupper():
                result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
            else:
                result.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
            key_index += 1
        else:
            result.append(ch)
    return "".join(result)


def xor_cipher_to_hex(text, key):
    if not key:
        raise ValueError("XOR key is required")
    text_bytes = text.encode("utf-8")
    key_bytes = key.encode("utf-8")
    encrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(text_bytes))
    return encrypted.hex()


def apply_encryption(text, method, key):
    if method == "Caesar Cipher":
        shift = int(key.strip()) if key.strip() else 3
        return caesar_cipher(text, shift)
    if method == "Vigenere Cipher":
        return vigenere_cipher(text, key)
    if method == "XOR Cipher":
        return xor_cipher_to_hex(text, key)
    if method == "ROT13":
        return caesar_cipher(text, 13)
    if method == "Reverse Text":
        return text[::-1]
    if method == "Base64 Encode":
        return base64.b64encode(text.encode("utf-8")).decode("utf-8")
    raise ValueError("Invalid encryption method")


def analyze_text(text, hash_value=None):
    total = len(text)
    letters = sum(1 for ch in text if ch.isalpha())
    digits = sum(1 for ch in text if ch.isdigit())
    spaces = sum(1 for ch in text if ch.isspace())
    symbols = total - letters - digits - spaces
    byte_size = len(text.encode("utf-8"))

    counter = Counter(ch.lower() for ch in text if ch.lower() in string.ascii_lowercase + string.digits)
    most_common = counter.most_common(8)
    repeated = ", ".join(f"{repr(ch)}={count}" for ch, count in most_common) if most_common else "No letters or digits found"

    lines = [
        "TEXT ANALYSIS",
        "-------------",
        f"Characters: {total}",
        f"Bytes: {byte_size}",
        f"Letters: {letters}",
        f"Digits: {digits}",
        f"Spaces: {spaces}",
        f"Symbols: {symbols}",
        f"Most repeated: {repeated}",
    ]

    if hash_value:
        hex_counter = Counter(hash_value.lower())
        hex_freq = ", ".join(f"{key}:{hex_counter[key]}" for key in sorted(hex_counter))
        lines += [
            "",
            "HASH HEX ANALYSIS",
            "-----------------",
            f"Hash length: {len(hash_value)} hex characters",
            f"Hex frequency: {hex_freq}",
        ]
    return "\n".join(lines)


def algorithm_note(algorithm):
    if algorithm in ["MD5", "SHA-1"]:
        return f"Note: {algorithm} is included for learning/comparison only. It is not recommended for real security."
    if algorithm.startswith("SHA3"):
        return "Note: SHA-3 is a modern hash family and is good to mention as extra research."
    return "Note: This algorithm is suitable for demonstrating message integrity in this project."


class CryptoHashApp:
    def __init__(self):
        ensure_user_file()
        self.root = tk.Tk()
        self.root.title(APP_TITLE)
        self.root.geometry("1200x760")
        self.root.minsize(1000, 650)
        try:
            self.root.state("zoomed")
        except Exception:
            pass
        self.root.configure(bg=BG)
        self.current_user = None
        self.selected_file = None
        self.show_home()

    def run(self):
        self.root.mainloop()

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def label(self, parent, text, size=11, weight="normal", fg=INK, bg=PAPER, **kwargs):
        return tk.Label(parent, text=text, font=("Segoe UI", size, weight), fg=fg, bg=bg, **kwargs)

    def button(self, parent, text, command, bg=TEAL, fg=WHITE, width=None):
        btn = tk.Button(
            parent, text=text, command=command, bg=bg, fg=fg, activebackground=bg,
            activeforeground=fg, relief="flat", bd=0, padx=18, pady=10, width=width,
            cursor="hand2", font=("Segoe UI", 10, "bold")
        )
        btn.bind("<Enter>", lambda e: btn.config(bg=self.mix(bg, 0.12)))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg))
        return btn

    def mix(self, color, amount):
        c = color.lstrip("#")
        r, g, b = int(c[:2], 16), int(c[2:4], 16), int(c[4:], 16)
        r = min(255, int(r + (255-r)*amount))
        g = min(255, int(g + (255-g)*amount))
        b = min(255, int(b + (255-b)*amount))
        return f"#{r:02x}{g:02x}{b:02x}"

    def entry(self, parent, show=None):
        return tk.Entry(
            parent, font=("Segoe UI", 11), bg=INPUT, fg=INK, relief="flat", bd=0,
            show=show, insertbackground=INK, highlightthickness=1,
            highlightbackground=LINE, highlightcolor=TEAL
        )

    def textbox(self, parent, height=8):
        return tk.Text(
            parent, height=height, font=("Consolas", 10), bg=INPUT, fg=INK,
            relief="flat", bd=0, wrap="word", padx=12, pady=10,
            insertbackground=INK, highlightthickness=1,
            highlightbackground=LINE, highlightcolor=TEAL
        )

    def set_text(self, box, value):
        box.config(state="normal")
        box.delete("1.0", tk.END)
        box.insert("1.0", value)
        box.config(state="normal")

    def get_text(self, box):
        return box.get("1.0", tk.END).strip()

    def copy_to_clipboard(self, text, label="Text"):
        if not text:
            messagebox.showwarning("Nothing to copy", f"No {label.lower()} available yet.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Copied", f"{label} copied to clipboard.")

    def option_menu(self, parent, var, values):
        menu = tk.OptionMenu(parent, var, *values)
        menu.config(
            bg=INPUT, fg=INK, activebackground=PAPER_2, activeforeground=INK,
            relief="flat", bd=0, font=("Segoe UI", 10, "bold"), cursor="hand2",
            highlightthickness=1, highlightbackground=LINE, highlightcolor=TEAL
        )
        menu["menu"].config(bg=INPUT, fg=INK, activebackground=PAPER_2, activeforeground=INK)
        return menu

    def form_label(self, parent, text, bg=PAPER):
        self.label(parent, text, 10, "bold", INK, bg).pack(anchor="w", pady=(8, 4))

    def make_scroll_area(self, parent, bg=BG):
        canvas = tk.Canvas(parent, bg=bg, bd=0, highlightthickness=0)
        scrollbar = tk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        frame = tk.Frame(canvas, bg=bg)
        window_id = canvas.create_window((0, 0), window=frame, anchor="nw")

        def update_scroll_region(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def resize_frame(event):
            # Keep the content width equal to the visible page width.
            canvas.itemconfig(window_id, width=event.width)

        def on_mousewheel(event):
            # Windows touchpad / mouse wheel support
            if event.delta:
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def on_linux_scroll_up(event):
            canvas.yview_scroll(-1, "units")

        def on_linux_scroll_down(event):
            canvas.yview_scroll(1, "units")

        frame.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", resize_frame)

        # Makes the whole page scroll even when the cursor is over a form box.
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        canvas.bind_all("<Button-4>", on_linux_scroll_up)
        canvas.bind_all("<Button-5>", on_linux_scroll_down)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        return frame

    # ---------- Layouts ----------
    def home_shell(self):
        self.clear()
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="both", expand=True)
        return outer

    def app_shell(self, page_title, subtitle):
        self.clear()
        sidebar = tk.Frame(self.root, bg=NAV, width=250)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="CryptoHash", font=("Segoe UI", 23, "bold"), fg=WHITE, bg=NAV).pack(anchor="w", padx=22, pady=(28, 0))
        tk.Label(sidebar, text="Student Lab", font=("Segoe UI", 12, "bold"), fg="#f4d38c", bg=NAV).pack(anchor="w", padx=24, pady=(0, 18))

        user_box = tk.Frame(sidebar, bg=NAV_2, padx=12, pady=10)
        user_box.pack(fill="x", padx=16, pady=(0, 18))
        tk.Label(user_box, text="signed in as", font=("Segoe UI", 8, "bold"), fg="#d4d9e8", bg=NAV_2).pack(anchor="w")
        tk.Label(user_box, text=self.current_user or "student", font=("Segoe UI", 11, "bold"), fg=WHITE, bg=NAV_2).pack(anchor="w")

        nav_items = [
            ("Home board", self.show_dashboard),
            ("Hash + encryption", self.show_hash_with_encryption),
            ("Hash only", self.show_hash_without_encryption),
            ("HMAC", self.show_hmac_page),
            ("File hashing", self.show_file_hashing_page),
            ("About project", self.show_about_page),
        ]
        for text, command in nav_items:
            b = tk.Button(
                sidebar, text=text, command=command, anchor="w", bg=NAV, fg="#edf2ff",
                activebackground=NAV_2, activeforeground=WHITE, bd=0, relief="flat",
                padx=22, pady=11, font=("Segoe UI", 10, "bold"), cursor="hand2"
            )
            b.pack(fill="x", padx=8, pady=2)
            b.bind("<Enter>", lambda e, btn=b: btn.config(bg=NAV_2))
            b.bind("<Leave>", lambda e, btn=b: btn.config(bg=NAV))

        tk.Frame(sidebar, height=1, bg="#59657f").pack(fill="x", padx=18, pady=18)
        self.button(sidebar, "Logout", self.logout, bg=ROSE).pack(fill="x", padx=18)

        main = tk.Frame(self.root, bg=BG)
        main.pack(side="left", fill="both", expand=True)

        header = tk.Frame(main, bg=BG)
        header.pack(fill="x", padx=28, pady=(24, 10))
        tk.Label(header, text=page_title, font=("Segoe UI", 24, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(header, text=subtitle, font=("Segoe UI", 10), fg=MUTED, bg=BG).pack(anchor="w", pady=(4, 0))

        body_holder = tk.Frame(main, bg=BG)
        body_holder.pack(fill="both", expand=True, padx=28, pady=(0, 24))
        return self.make_scroll_area(body_holder, BG)

    def card(self, parent, padx=22, pady=18, fill="x"):
        frame = tk.Frame(parent, bg=PAPER, padx=padx, pady=pady, highlightthickness=1, highlightbackground=LINE)
        frame.pack(fill=fill, padx=2, pady=10)
        return frame

    def two_columns(self, parent):
        # Stacked layout fits laptop screens better than two squeezed columns.
        # Input appears first, then the result/analysis box appears under it.
        left = tk.Frame(parent, bg=BG)
        left.pack(fill="x", expand=False)

        right = tk.Frame(parent, bg=BG)
        right.pack(fill="both", expand=True, pady=(8, 0))

        return left, right

    # ---------- Home / Login / Register ----------
    def show_home(self):
        self.current_user = None
        outer = self.home_shell()

        top = tk.Frame(outer, bg=BG)
        top.pack(fill="x", padx=42, pady=26)
        tk.Label(top, text="Cybersecurity Fundementals Project", font=("Segoe UI", 15, "bold"), fg=INK, bg=BG).pack(side="left")
        self.button(top, "Login", self.show_login, bg=TEAL).pack(side="right", padx=(8, 0))
        self.button(top, "Register", self.show_register, bg=NAV).pack(side="right")

        hero = tk.Frame(outer, bg=BG)
        hero.pack(fill="both", expand=True, padx=42, pady=(8, 42))

        left = tk.Frame(hero, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 24))
        right = tk.Frame(hero, bg=PAPER, padx=26, pady=24, highlightthickness=1, highlightbackground=LINE)
        right.pack(side="left", fill="both", expand=True)

        tk.Label(left, text="CryptoHash Analyzer", font=("Segoe UI", 34, "bold"), fg=INK, bg=BG, justify="left").pack(anchor="w", pady=(30, 14))
        tk.Label(left, text="A simple lab tool that helps users test common hashing algorithms, apply simple encryption before hashing, generate HMAC values, and create file hashes for integrity checking.", font=("Segoe UI", 12), fg=MUTED, bg=BG, wraplength=500, justify="left").pack(anchor="w")
        self.button(left, "Start with login", self.show_login, bg=TEAL).pack(anchor="w", pady=26)

        canvas = tk.Canvas(right, height=230, bg=PAPER, bd=0, highlightthickness=0)
        canvas.pack(fill="x", pady=(0, 16))
        canvas.create_rectangle(55, 35, 420, 205, fill=PAPER_2, outline=LINE, width=2)
        canvas.create_text(95, 68, text="input.txt", fill=MUTED, font=("Segoe UI", 11, "bold"), anchor="w")
        canvas.create_text(95, 105, text="message  →  SHA-256", fill=INK, font=("Consolas", 14, "bold"), anchor="w")
        canvas.create_rectangle(95, 132, 380, 158, fill=INPUT, outline=LINE)
        canvas.create_text(108, 145, text="a7c3...9fd1", fill=TEAL_DARK, font=("Consolas", 12, "bold"), anchor="w")
        canvas.create_oval(400, 30, 470, 100, fill=TEAL, outline="")
        canvas.create_text(435, 65, text="#", fill=WHITE, font=("Segoe UI", 26, "bold"))
        canvas.create_line(420, 100, 455, 145, fill=AMBER, width=4)
        canvas.create_line(455, 145, 420, 190, fill=AMBER, width=4)

        notes = [
            "• Generate hashes using MD5, SHA-1, SHA-2, and SHA-3",
            "• Try educational encryption before hashing",
            "• Create HMAC using a secret key",
            "• Verify if a message hash matches",
            "• Generate file hashes for integrity comparison",
        ]
        for item in notes:
            tk.Label(right, text=item, font=("Segoe UI", 12), fg=INK, bg=PAPER).pack(anchor="w", pady=5)

    def auth_layout(self, title, subtitle):
        outer = self.home_shell()
        box = tk.Frame(outer, bg=PAPER, padx=30, pady=26, highlightthickness=1, highlightbackground=LINE)
        box.place(relx=0.5, rely=0.5, anchor="center", width=460)
        tk.Label(box, text=title, font=("Segoe UI", 25, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        tk.Label(box, text=subtitle, font=("Segoe UI", 10), fg=MUTED, bg=PAPER, wraplength=380, justify="left").pack(anchor="w", pady=(4, 18))
        return box

    def show_login(self):
        box = self.auth_layout("Login", "Enter your saved username and password to open the project menu.")
        self.form_label(box, "Username")
        username = self.entry(box)
        username.pack(fill="x", ipady=9)
        self.form_label(box, "Password")
        password = self.entry(box, show="*")
        password.pack(fill="x", ipady=9)

        def login():
            u = username.get().strip()
            p = password.get().strip()
            if not u or not p:
                messagebox.showerror("Missing data", "Please enter username and password.")
                return
            for user in load_users():
                if user.get("username") == u and verify_password(p, user.get("salt", ""), user.get("password_hash", "")):
                    self.current_user = u
                    self.show_dashboard()
                    return
            messagebox.showerror("Login failed", "Username or password is not correct.")

        row = tk.Frame(box, bg=PAPER)
        row.pack(fill="x", pady=(18, 0))
        self.button(row, "Login", login, bg=TEAL).pack(side="left")
        self.button(row, "Create account", self.show_register, bg=NAV).pack(side="left", padx=8)
        self.button(row, "Back", self.show_home, bg=AMBER).pack(side="right")

    def show_register(self):
        box = self.auth_layout("Register", "Create a local account. The information is saved in data/users.json.")
        self.form_label(box, "Full name")
        fullname = self.entry(box)
        fullname.pack(fill="x", ipady=9)
        self.form_label(box, "Username")
        username = self.entry(box)
        username.pack(fill="x", ipady=9)
        self.form_label(box, "Password")
        password = self.entry(box, show="*")
        password.pack(fill="x", ipady=9)
        self.form_label(box, "Confirm password")
        confirm = self.entry(box, show="*")
        confirm.pack(fill="x", ipady=9)

        def register():
            name = fullname.get().strip()
            u = username.get().strip()
            p = password.get().strip()
            c = confirm.get().strip()
            if not name or not u or not p or not c:
                messagebox.showerror("Missing data", "Please fill all fields.")
                return
            if len(u) < 3:
                messagebox.showerror("Invalid username", "Username must be at least 3 characters.")
                return
            if len(p) < 6:
                messagebox.showerror("Weak password", "Password must be at least 6 characters.")
                return
            if p != c:
                messagebox.showerror("Password mismatch", "Confirm password does not match.")
                return
            users = load_users()
            if any(user.get("username") == u for user in users):
                messagebox.showerror("Username exists", "Please choose another username.")
                return
            salt, password_hash = hash_password(p)
            users.append({"fullname": name, "username": u, "salt": salt, "password_hash": password_hash})
            save_users(users)
            messagebox.showinfo("Account created", "Registration completed. You can login now.")
            self.show_login()

        row = tk.Frame(box, bg=PAPER)
        row.pack(fill="x", pady=(18, 0))
        self.button(row, "Register", register, bg=TEAL).pack(side="left")
        self.button(row, "Already have account", self.show_login, bg=NAV).pack(side="left", padx=8)
        self.button(row, "Back", self.show_home, bg=AMBER).pack(side="right")

    def logout(self):
        self.current_user = None
        self.show_home()

    # ---------- Dashboard ----------
    def show_dashboard(self):
        body = self.app_shell("Home board", "Choose a cryptography tool to generate hashes, verify message integrity, or check file fingerprints.")

        intro = self.card(body)
        tk.Label(intro, text="Project Overview", font=("Segoe UI", 18, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        tk.Label(intro, text="Main features of the CryptoHash Analyzer project.", font=("Segoe UI", 10), fg=MUTED, bg=PAPER).pack(anchor="w", pady=(4, 0))

        grid = tk.Frame(body, bg=BG)
        grid.pack(fill="both", expand=True)
        items = [
            ("Hash + Encryption", "Encrypt text first, hash it, and verify it on the same page.", self.show_hash_with_encryption, TEAL),
            ("Hash Only", "Generate a normal hash, analyze it, and verify it on the same page.", self.show_hash_without_encryption, BLUE),
            ("HMAC", "Use a secret key to authenticate a message.", self.show_hmac_page, PURPLE),
            ("File Hashing", "Generate file fingerprints for comparison.", self.show_file_hashing_page, AMBER),
            ("About Project", "Short explanation for discussion.", self.show_about_page, ROSE),
        ]
        for i, (title, desc, cmd, color) in enumerate(items):
            card = tk.Frame(grid, bg=PAPER, padx=18, pady=16, highlightthickness=1, highlightbackground=LINE)
            card.grid(row=i//3, column=i%3, sticky="nsew", padx=8, pady=8)
            grid.columnconfigure(i%3, weight=1)
            grid.rowconfigure(i//3, weight=1)
            tk.Label(card, text=title, font=("Segoe UI", 14, "bold"), fg=color, bg=PAPER).pack(anchor="w")
            tk.Label(card, text=desc, font=("Segoe UI", 10), fg=MUTED, bg=PAPER, wraplength=245, justify="left").pack(anchor="w", pady=(6, 12))
            self.button(card, "Open", cmd, bg=color).pack(anchor="w")

    # ---------- Feature pages ----------
    def show_hash_with_encryption(self):
        body = self.app_shell("Hash with encryption", "Encrypt the text first, then generate or verify its hash on the same page.")
        left, right = self.two_columns(body)

        form = self.card(left, fill="both")
        tk.Label(form, text="Input", font=("Segoe UI", 16, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        self.form_label(form, "Message")
        msg = self.textbox(form, height=6)
        msg.pack(fill="x")

        self.form_label(form, "Encryption method")
        enc_var = tk.StringVar(value=ENCRYPTION_METHODS[0])
        self.option_menu(form, enc_var, ENCRYPTION_METHODS).pack(fill="x")
        self.form_label(form, "Encryption key / shift")
        key = self.entry(form)
        key.pack(fill="x", ipady=8)
        self.form_label(form, "Hash algorithm")
        alg_var = tk.StringVar(value="SHA-256")
        self.option_menu(form, alg_var, HASH_ALGORITHMS).pack(fill="x")

        verify_box = tk.Frame(form, bg=PAPER_2, padx=12, pady=10, highlightthickness=1, highlightbackground=LINE)
        verify_box.pack(fill="x", pady=(14, 0))
        tk.Label(verify_box, text="Optional verification", font=("Segoe UI", 12, "bold"), fg=INK, bg=PAPER_2).pack(anchor="w")
        tk.Label(verify_box, text="Paste a received hash here to compare it with the new encrypted hash.", font=("Segoe UI", 9), fg=MUTED, bg=PAPER_2, wraplength=420, justify="left").pack(anchor="w", pady=(2, 6))
        received = self.textbox(verify_box, height=3)
        received.pack(fill="x")

        result = self.card(right, fill="both")
        tk.Label(result, text="Result and analysis", font=("Segoe UI", 16, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        out = self.textbox(result, height=12)
        out.pack(fill="both", expand=True, pady=(8, 0))

        last_hash = {"value": ""}

        def calculate_hash(show_verify=False):
            text = self.get_text(msg)
            if not text:
                messagebox.showerror("Missing message", "Please enter a message.")
                return
            try:
                encrypted = apply_encryption(text, enc_var.get(), key.get())
                hash_value = generate_hash(encrypted, alg_var.get())
                last_hash["value"] = hash_value

                verification_text = ""
                old_hash = self.get_text(received).replace(" ", "").replace("\n", "").lower()
                if show_verify or old_hash:
                    if not old_hash:
                        verification_text = "\nVERIFICATION\n------------\nPaste a received hash first, then press Verify.\n"
                    else:
                        status = "MATCH: Message integrity is preserved." if hmac.compare_digest(hash_value.lower(), old_hash) else "MISMATCH: Message may be changed."
                        verification_text = f"\nVERIFICATION\n------------\n{status}\nReceived hash:\n{old_hash}\n"

                output = (
                    f"Encryption method: {enc_var.get()}\n"
                    f"Hash algorithm: {alg_var.get()}\n\n"
                    f"Encrypted / processed text:\n{encrypted}\n\n"
                    f"Hash value:\n{hash_value}\n"
                    f"{verification_text}\n"
                    f"{analyze_text(encrypted, hash_value)}\n\n"
                    f"{algorithm_note(alg_var.get())}"
                )
                self.set_text(out, output)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        button_row = tk.Frame(form, bg=PAPER)
        button_row.pack(fill="x", pady=16)
        self.button(button_row, "Generate hash", lambda: calculate_hash(False), bg=TEAL).pack(side="left")
        self.button(button_row, "Verify received hash", lambda: calculate_hash(True), bg=GREEN).pack(side="left", padx=8)
        self.button(button_row, "Copy hash", lambda: self.copy_to_clipboard(last_hash["value"], "Hash value"), bg=NAV).pack(side="left")

    def show_hash_without_encryption(self):
        body = self.app_shell("Hash only", "Generate a normal hash directly from the message, then verify it on the same page if needed.")
        left, right = self.two_columns(body)

        form = self.card(left, fill="both")
        tk.Label(form, text="Message", font=("Segoe UI", 16, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        msg = self.textbox(form, height=7)
        msg.pack(fill="x", pady=(8, 0))
        self.form_label(form, "Hash algorithm")
        alg_var = tk.StringVar(value="SHA-256")
        self.option_menu(form, alg_var, HASH_ALGORITHMS).pack(fill="x")

        verify_box = tk.Frame(form, bg=PAPER_2, padx=12, pady=10, highlightthickness=1, highlightbackground=LINE)
        verify_box.pack(fill="x", pady=(14, 0))
        tk.Label(verify_box, text="Optional verification", font=("Segoe UI", 12, "bold"), fg=INK, bg=PAPER_2).pack(anchor="w")
        tk.Label(verify_box, text="Paste a received hash here to compare it with the new hash.", font=("Segoe UI", 9), fg=MUTED, bg=PAPER_2, wraplength=420, justify="left").pack(anchor="w", pady=(2, 6))
        received = self.textbox(verify_box, height=3)
        received.pack(fill="x")

        result = self.card(right, fill="both")
        tk.Label(result, text="Hash, verification, and analysis", font=("Segoe UI", 16, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        out = self.textbox(result, height=12)
        out.pack(fill="both", expand=True, pady=(8, 0))

        last_hash = {"value": ""}

        def calculate_hash(show_verify=False):
            text = self.get_text(msg)
            if not text:
                messagebox.showerror("Missing message", "Please enter a message.")
                return
            try:
                hash_value = generate_hash(text, alg_var.get())
                last_hash["value"] = hash_value

                verification_text = ""
                old_hash = self.get_text(received).replace(" ", "").replace("\n", "").lower()
                if show_verify or old_hash:
                    if not old_hash:
                        verification_text = "\nVERIFICATION\n------------\nPaste a received hash first, then press Verify.\n"
                    else:
                        status = "MATCH: Message integrity is preserved." if hmac.compare_digest(hash_value.lower(), old_hash) else "MISMATCH: Message may be changed."
                        verification_text = f"\nVERIFICATION\n------------\n{status}\nReceived hash:\n{old_hash}\n"

                output = (
                    f"Hash algorithm: {alg_var.get()}\n\n"
                    f"Hash value:\n{hash_value}\n"
                    f"{verification_text}\n"
                    f"{analyze_text(text, hash_value)}\n\n"
                    f"{algorithm_note(alg_var.get())}"
                )
                self.set_text(out, output)
            except Exception as exc:
                messagebox.showerror("Error", str(exc))

        button_row = tk.Frame(form, bg=PAPER)
        button_row.pack(fill="x", pady=16)
        self.button(button_row, "Generate hash", lambda: calculate_hash(False), bg=BLUE).pack(side="left")
        self.button(button_row, "Verify received hash", lambda: calculate_hash(True), bg=GREEN).pack(side="left", padx=8)
        self.button(button_row, "Copy hash", lambda: self.copy_to_clipboard(last_hash["value"], "Hash value"), bg=NAV).pack(side="left")

    def show_hmac_page(self):
        body = self.app_shell("Message Authentication Code (HMAC)", "HMAC uses a secret key with the message, which is stronger than a normal hash for authentication.")
        left, right = self.two_columns(body)

        form = self.card(left, fill="both")
        tk.Label(form, text="HMAC input", font=("Segoe UI", 16, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        self.form_label(form, "Message")
        msg = self.textbox(form, height=8)
        msg.pack(fill="x")
        self.form_label(form, "Secret key")
        secret = self.entry(form, show="*")
        secret.pack(fill="x", ipady=8)
        self.form_label(form, "HMAC algorithm")
        alg_var = tk.StringVar(value="HMAC-SHA256")
        self.option_menu(form, alg_var, HMAC_ALGORITHMS).pack(fill="x")

        result = self.card(right, fill="both")
        tk.Label(result, text="HMAC result", font=("Segoe UI", 16, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        out = self.textbox(result, height=12)
        out.pack(fill="both", expand=True, pady=(8, 0))

        last_hmac = {"value": ""}

        def run_hmac():
            text = self.get_text(msg)
            key = secret.get().strip()
            if not text or not key:
                messagebox.showerror("Missing data", "Message and secret key are required.")
                return
            alg = alg_var.get()
            digest = hashlib.sha256
            if alg == "HMAC-SHA512":
                digest = hashlib.sha512
            elif alg == "HMAC-SHA3-256":
                digest = hashlib.sha3_256
            value = hmac.new(key.encode("utf-8"), text.encode("utf-8"), digest).hexdigest()
            last_hmac["value"] = value
            self.set_text(out, f"Algorithm: {alg}\n\nHMAC value:\n{value}\n\nExplanation:\nThe secret key is not sent with the message. The receiver must know the same key to calculate the same HMAC.")

        row = tk.Frame(form, bg=PAPER)
        row.pack(fill="x", pady=16)
        self.button(row, "Generate HMAC", run_hmac, bg=PURPLE).pack(side="left")
        self.button(row, "Copy HMAC", lambda: self.copy_to_clipboard(last_hmac["value"], "HMAC value"), bg=NAV).pack(side="left", padx=8)

    def show_file_hashing_page(self):
        body = self.app_shell("File hashing", "Generate file hashes that can be compared later for integrity checking.")
        card = self.card(body, fill="both")
        tk.Label(card, text="Choose a file", font=("Segoe UI", 16, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        info = tk.Label(card, text="No file selected", font=("Segoe UI", 10), fg=MUTED, bg=PAPER)
        info.pack(anchor="w", pady=(6, 12))
        out = self.textbox(card, height=13)
        out.pack(fill="both", expand=True, pady=(12, 0))

        file_hashes = {"sha256": "", "sha512": "", "sha3": "", "all": ""}

        def choose_file():
            path = filedialog.askopenfilename(title="Choose a file to hash")
            if not path:
                return
            self.selected_file = path
            info.config(text=os.path.basename(path))
            try:
                with open(path, "rb") as f:
                    data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                sha512 = hashlib.sha512(data).hexdigest()
                sha3 = hashlib.sha3_256(data).hexdigest()
                result_text = (
                    f"File name: {os.path.basename(path)}\n"
                    f"File size: {len(data)} bytes\n\n"
                    f"SHA-256:\n{sha256}\n\n"
                    f"SHA-512:\n{sha512}\n\n"
                    f"SHA3-256:\n{sha3}\n\n"
                    "How to use it:\n"
                    "Save one of these hashes, then hash the same file later. If the new hash is different, the file was edited or corrupted."
                )
                file_hashes["sha256"] = sha256
                file_hashes["sha512"] = sha512
                file_hashes["sha3"] = sha3
                file_hashes["all"] = result_text
                self.set_text(out, result_text)
            except Exception as exc:
                messagebox.showerror("File error", str(exc))

        row = tk.Frame(card, bg=PAPER)
        row.pack(fill="x", pady=(4, 0))
        self.button(row, "Choose file and generate hashes", choose_file, bg=AMBER).pack(side="left")
        self.button(row, "Copy SHA-256", lambda: self.copy_to_clipboard(file_hashes["sha256"], "SHA-256 file hash"), bg=NAV).pack(side="left", padx=8)
        self.button(row, "Copy all", lambda: self.copy_to_clipboard(file_hashes["all"], "File hash results"), bg=TEAL).pack(side="left")

    def show_about_page(self):
        body = self.app_shell("About project", "Short notes you can use in discussion.")
        card = self.card(body, fill="both")
        tk.Label(card, text="Project explanation", font=("Segoe UI", 17, "bold"), fg=INK, bg=PAPER).pack(anchor="w")
        text = (
            "CryptoHash Analyzer is a cybersecurity fundamentals project. It demonstrates how hash functions create a fixed-size digest from text or files.\n\n"
            "Main features:\n"
            "1. Hash without encryption: generates a normal hash and shows analysis.\n"
            "2. Hash with encryption: applies an educational encryption method first, then hashes the result.\n"
            "3. HMAC: uses a secret key with the message for authentication.\n"
            "4. Verify hash: compares a computed hash with a received hash to check integrity.\n"
            "5. File hashing: creates file fingerprints using SHA-256, SHA-512, and SHA3-256.\n\n"
            "Important notes:\n"
            "• Hashing is one-way, not encryption.\n"
            "• Caesar, Vigenere, XOR, ROT13, Reverse Text, and Base64 are included for learning only.\n"
            "• MD5 and SHA-1 are weak and included for comparison only.\n"
            "• File hashing becomes integrity checking when the new file hash is compared with the original saved hash."
        )
        box = self.textbox(card, height=16)
        box.pack(fill="both", expand=True, pady=(12, 0))
        self.set_text(box, text)


if __name__ == "__main__":
    app = CryptoHashApp()
    app.run()
