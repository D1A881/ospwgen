#!/usr/bin/env python3
"""
ospwgen_gui.py - Tkinter front end for ospwgen (Old School Password Generator)

Reimplements the logic of ospwgen.c (https://github.com/D1A881/ospwgen) in pure
Python, using the `secrets` module (CSPRNG) in place of arc4random_uniform()/
/dev/urandom, and presents it as a tabbed GUI with three modes:

  1. Format Generator   - build passwords from a pattern string (u l c v C V d s r)
  2. Random Generator   - generate N passwords of length L from the full character set
  3. Format Analyzer    - convert an existing password into its format string (F / FS)

Each mode supports the same output options as the CLI: plain, hex, HEX,
hex-only, HEX-only, or JSON.
"""

import json
import secrets
import tkinter as tk
from tkinter import ttk, messagebox

# ----------------------------------------------------------------------------
# Core logic - ported directly from ospwgen.c
# ----------------------------------------------------------------------------

VER = 0x0216
REV = 0
MAX_PASSWORD_LENGTH = 256
DEFAULT_PASSWORD_LENGTH = 15

A_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A_UPPERC = "BCDFGHJKLMNPQRSTVWXYZ"
A_UPPERV = "AEIOU"
A_LOWER = "abcdefghijklmnopqrstuvwxyz"
A_LOWERC = "bcdfghjklmnpqrstvwxyz"
A_LOWERV = "aeiou"
A_DIGIT = "0123456789"
A_SYMBL = "!@#$%^&*()-+;:,."
A_ALL = A_UPPER + A_LOWER + A_DIGIT + A_SYMBL
A_FSTR = "ulcvCVdsr"

FORMAT_MAP = {
    "u": A_UPPER, "l": A_LOWER, "c": A_LOWERC, "v": A_LOWERV,
    "C": A_UPPERC, "V": A_UPPERV, "d": A_DIGIT, "s": A_SYMBL, "r": A_ALL,
}

FORMAT_LABELS = {
    "u": "uppercase letter", "l": "lowercase letter", "c": "consonant",
    "v": "vowel", "C": "uppercase consonant", "V": "uppercase vowel",
    "d": "digit", "s": "symbol", "r": "random printable character",
}


def secure_choice(charset: str) -> str:
    """Crypto-secure equivalent of pw_rand()-driven character selection."""
    return secrets.choice(charset)


def generate_random_password(length: int) -> str:
    return "".join(secure_choice(A_ALL) for _ in range(length))


def generate_from_format(fmt: str) -> str:
    return "".join(secure_choice(FORMAT_MAP[c]) for c in fmt)


def validate_format(fmt: str):
    if not fmt:
        raise ValueError("Format string must not be empty.")
    if len(fmt) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Format string must be {MAX_PASSWORD_LENGTH} characters or less.")
    for i, ch in enumerate(fmt):
        if ch not in A_FSTR:
            raise ValueError(f"Invalid character '{ch}' at position {i + 1}.")


def password_to_format(password: str, specific: bool) -> str:
    if not password:
        raise ValueError("Password must not be empty.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"Password must be {MAX_PASSWORD_LENGTH} characters or less.")
    out = []
    for c in password:
        if c.isdigit():
            out.append("d")
        elif c in A_SYMBL:
            out.append("s")
        elif "A" <= c <= "Z":
            out.append(("V" if c in A_UPPERV else "C") if specific else "u")
        elif "a" <= c <= "z":
            out.append(("v" if c in A_LOWERV else "c") if specific else "l")
        else:
            out.append("r")
    return "".join(out)


def to_hex(s: str, upper: bool) -> str:
    h = s.encode("utf-8", errors="replace").hex()
    return h.upper() if upper else h


def format_output(passwords, hex_mode, json_mode):
    """
    hex_mode: one of None, 'h', 'H', 'h0', 'H0'
    json_mode: bool
    Returns a list of display strings (or a single JSON string if json_mode).
    """
    if json_mode:
        items = [{"password": p, "hex": to_hex(p, False)} for p in passwords]
        data = items[0] if len(items) == 1 else items
        return [json.dumps(data, indent=2)]

    lines = []
    for p in passwords:
        if hex_mode in (None, "none"):
            lines.append(p)
        elif hex_mode == "h":
            lines.append(f"{p}\n{to_hex(p, False)}")
        elif hex_mode == "H":
            lines.append(f"{p}\n{to_hex(p, True)}")
        elif hex_mode == "h0":
            lines.append(to_hex(p, False))
        elif hex_mode == "H0":
            lines.append(to_hex(p, True))
    return lines


HELP_TEXT = f"""\
    ,-. ,-. ;-. , , , ,-: ,-. ;-.
    | | `-. | | |/|/  | | |-' | |
    `-' `-' |-' ' '   `-| `-' ' '
            '         `-'        
Old School Password Generator - v{VER:04x} r{REV:02x}
©2022-2026 by billy@slack.net
https://github.com/D1A881/ospwgen

Format string characters:
  u = uppercase letter        l = lowercase letter
  c = consonant               v = vowel
  C = uppercase consonant     V = uppercase vowel
  d = digit                   s = symbol
  r = random printable character

Random passwords:
  Choose a length and a count; characters are drawn uniformly from the
  full set (upper + lower + digits + symbols) using a CSPRNG.

Password to format string:
  F  mode converts each character of a password to its format specifier.
  FS mode is like F, but distinguishes consonant/vowel within each case.

Output options:
  none      - plain password text
  h / H     - password followed by lower/upper-case hex
  h0 / H0   - hex only (lower/upper-case)
  JSON      - {{"password": "...", "hex": "..."}} (array if multiple)
"""

# ----------------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------------

class OutputOptions(ttk.LabelFrame):
    """Reusable widget: hex/JSON output mode selector."""

    def __init__(self, master):
        super().__init__(master, text="Output format", padding=10)
        self.mode = tk.StringVar(value="none")
        options = [
            ("Plain text", "none"),
            ("Plain + lowercase hex (h)", "h"),
            ("Plain + UPPERCASE hex (H)", "H"),
            ("Hex only, lowercase (h0)", "h0"),
            ("Hex only, UPPERCASE (H0)", "H0"),
            ("JSON (j)", "json"),
        ]
        for i, (label, val) in enumerate(options):
            ttk.Radiobutton(self, text=label, value=val, variable=self.mode).grid(
                row=i // 2, column=i % 2, sticky="w", padx=4, pady=2
            )

    def get(self):
        v = self.mode.get()
        if v == "json":
            return None, True
        if v == "none":
            return None, False
        return v, False


class OutputPanel(ttk.LabelFrame):
    """Reusable widget: results list + copy/save/clear actions."""

    def __init__(self, master):
        super().__init__(master, text="Results", padding=10)
        self.text = tk.Text(self, height=12, width=60, wrap="word", font=("Consolas", 10))
        scroll = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.grid(row=0, column=0, columnspan=3, sticky="nsew")
        scroll.grid(row=0, column=3, sticky="ns")

        ttk.Button(self, text="Copy all", command=self.copy_all).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Button(self, text="Save to file...", command=self.save_to_file).grid(row=1, column=1, sticky="w", pady=(6, 0))
        ttk.Button(self, text="Clear", command=self.clear).grid(row=1, column=2, sticky="w", pady=(6, 0))

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def show(self, lines):
        self.text.delete("1.0", tk.END)
        self.text.insert(tk.END, "\n\n---\n\n".join(lines) if len(lines) > 1 else lines[0])

    def copy_all(self):
        content = self.text.get("1.0", tk.END).strip()
        if not content:
            return
        self.clipboard_clear()
        self.clipboard_append(content)

    def save_to_file(self):
        from tkinter import filedialog
        content = self.text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Nothing to save", "Generate output first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content + "\n")

    def clear(self):
        self.text.delete("1.0", tk.END)


class FormatTab(ttk.Frame):
    """Format-string generation mode (u/l/c/v/C/V/d/s/r)."""

    def __init__(self, master, output_panel: OutputPanel):
        super().__init__(master, padding=12)
        self.output_panel = output_panel

        builder = ttk.LabelFrame(self, text="Format string", padding=10)
        builder.grid(row=0, column=0, sticky="ew")
        builder.columnconfigure(1, weight=1)

        ttk.Label(builder, text="Pattern:").grid(row=0, column=0, sticky="w")
        self.fmt_var = tk.StringVar(value="ulcvCVds")
        entry = ttk.Entry(builder, textvariable=self.fmt_var, font=("Consolas", 11))
        entry.grid(row=0, column=1, sticky="ew", padx=6)

        # Insert-character helper buttons
        btn_row = ttk.Frame(builder)
        btn_row.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        for ch in A_FSTR:
            b = ttk.Button(btn_row, text=ch, width=3,
                            command=lambda c=ch: self._insert(c))
            b.pack(side="left", padx=2)
            self._add_tooltip(b, f"{ch} = {FORMAT_LABELS[ch]}")

        legend = "  ".join(f"{c}={FORMAT_LABELS[c]}" for c in A_FSTR)
        ttk.Label(builder, text=legend, wraplength=520, foreground="#555").grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )

        opts = ttk.Frame(self)
        opts.grid(row=1, column=0, sticky="ew", pady=10)
        ttk.Label(opts, text="Count:").grid(row=0, column=0, sticky="w")
        self.count_var = tk.IntVar(value=1)
        ttk.Spinbox(opts, from_=1, to=1000, textvariable=self.count_var, width=8).grid(
            row=0, column=1, sticky="w", padx=6
        )

        self.output_opts = OutputOptions(self)
        self.output_opts.grid(row=2, column=0, sticky="ew")

        ttk.Button(self, text="Generate", command=self.generate).grid(
            row=3, column=0, sticky="w", pady=10
        )

        self.columnconfigure(0, weight=1)

    def _insert(self, ch):
        self.fmt_var.set(self.fmt_var.get() + ch)

    def _add_tooltip(self, widget, text):
        tip = tk.Toplevel(widget)
        tip.withdraw()
        tip.overrideredirect(True)
        label = tk.Label(tip, text=text, background="#ffffe0", relief="solid", borderwidth=1, padx=4, pady=2)
        label.pack()

        def enter(e):
            x = widget.winfo_rootx() + 10
            y = widget.winfo_rooty() + widget.winfo_height() + 5
            tip.geometry(f"+{x}+{y}")
            tip.deiconify()

        def leave(e):
            tip.withdraw()

        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def generate(self):
        fmt = self.fmt_var.get()
        try:
            validate_format(fmt)
            count = int(self.count_var.get())
            if count < 1:
                raise ValueError("Count must be at least 1.")
            hex_mode, json_mode = self.output_opts.get()
            passwords = [generate_from_format(fmt) for _ in range(count)]
            lines = format_output(passwords, hex_mode, json_mode)
            self.output_panel.show(lines)
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))


class RandomTab(ttk.Frame):
    """Random password generation mode (R length count)."""

    def __init__(self, master, output_panel: OutputPanel):
        super().__init__(master, padding=12)
        self.output_panel = output_panel

        opts = ttk.LabelFrame(self, text="Random password settings", padding=10)
        opts.grid(row=0, column=0, sticky="ew")

        ttk.Label(opts, text="Length:").grid(row=0, column=0, sticky="w")
        self.length_var = tk.IntVar(value=DEFAULT_PASSWORD_LENGTH)
        ttk.Spinbox(opts, from_=1, to=MAX_PASSWORD_LENGTH, textvariable=self.length_var, width=8).grid(
            row=0, column=1, sticky="w", padx=6
        )

        ttk.Label(opts, text="Count:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.count_var = tk.IntVar(value=1)
        ttk.Spinbox(opts, from_=1, to=1000, textvariable=self.count_var, width=8).grid(
            row=1, column=1, sticky="w", padx=6, pady=(6, 0)
        )

        ttk.Label(
            self,
            text="Characters drawn uniformly from: A-Z a-z 0-9 !@#$%^&*()-+;:,.",
            foreground="#555",
        ).grid(row=1, column=0, sticky="w", pady=(6, 10))

        self.output_opts = OutputOptions(self)
        self.output_opts.grid(row=2, column=0, sticky="ew")

        ttk.Button(self, text="Generate", command=self.generate).grid(
            row=3, column=0, sticky="w", pady=10
        )

        self.columnconfigure(0, weight=1)

    def generate(self):
        try:
            length = int(self.length_var.get())
            count = int(self.count_var.get())
            if not (1 <= length <= MAX_PASSWORD_LENGTH):
                raise ValueError(f"Length must be between 1 and {MAX_PASSWORD_LENGTH}.")
            if count < 1:
                raise ValueError("Count must be at least 1.")
            hex_mode, json_mode = self.output_opts.get()
            passwords = [generate_random_password(length) for _ in range(count)]
            lines = format_output(passwords, hex_mode, json_mode)
            self.output_panel.show(lines)
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))


class AnalyzeTab(ttk.Frame):
    """Password -> format string conversion mode (F / FS)."""

    def __init__(self, master, output_panel: OutputPanel):
        super().__init__(master, padding=12)
        self.output_panel = output_panel

        box = ttk.LabelFrame(self, text="Analyze an existing password", padding=10)
        box.grid(row=0, column=0, sticky="ew")
        box.columnconfigure(1, weight=1)

        ttk.Label(box, text="Password:").grid(row=0, column=0, sticky="w")
        self.pw_var = tk.StringVar()
        self.show_var = tk.BooleanVar(value=False)
        self.entry = ttk.Entry(box, textvariable=self.pw_var, show="*", font=("Consolas", 11))
        self.entry.grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Checkbutton(box, text="Show", variable=self.show_var, command=self._toggle_show).grid(
            row=0, column=2, sticky="w"
        )

        self.specific_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            box,
            text="FS mode (distinguish consonant/vowel per case, not just upper/lower)",
            variable=self.specific_var,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        ttk.Button(self, text="Analyze", command=self.analyze).grid(row=1, column=0, sticky="w", pady=10)

        self.columnconfigure(0, weight=1)

    def _toggle_show(self):
        self.entry.configure(show="" if self.show_var.get() else "*")

    def analyze(self):
        try:
            fmt = password_to_format(self.pw_var.get(), self.specific_var.get())
            self.output_panel.show([f"Password length: {len(self.pw_var.get())}\nFormat string:   {fmt}"])
        except ValueError as e:
            messagebox.showerror("Invalid input", str(e))


class AboutTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=12)
        text = tk.Text(self, wrap="word", font=("Consolas", 10), height=24, width=70)
        text.insert(tk.END, HELP_TEXT)
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)


class OspwgenApp(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.pack(fill="both", expand=True)

        title = ttk.Label(self, text="ospwgen — Old School Password Generator",
                           font=("Segoe UI", 14, "bold"))
        title.pack(anchor="w", pady=(0, 8))

        body = ttk.Frame(self)
        body.pack(fill="both", expand=True)

        left = ttk.Frame(body)
        left.pack(side="left", fill="both", expand=True)

        notebook = ttk.Notebook(left)
        notebook.pack(fill="both", expand=True)

        right = ttk.Frame(body)
        right.pack(side="left", fill="both", expand=True, padx=(10, 0))

        self.output_panel = OutputPanel(right)
        self.output_panel.pack(fill="both", expand=True)

        notebook.add(FormatTab(notebook, self.output_panel), text="Format Generator")
        notebook.add(RandomTab(notebook, self.output_panel), text="Random Generator")
        notebook.add(AnalyzeTab(notebook, self.output_panel), text="Analyze (F/FS)")
        notebook.add(AboutTab(notebook), text="Help / About")


def main():
    root = tk.Tk()
    root.title("ospwgen GUI")
    root.geometry("980x560")
    root.minsize(860, 480)

    try:
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass

    OspwgenApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
