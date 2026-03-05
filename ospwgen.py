#!/usr/bin/env python3
"""
ospwgen.py - Old School Password Generator
©2022-2026 by billy@slack.net
https://github.com/D1A881/ospwgen
"""

import sys
import json
import secrets

VER = 0x0216
REV = 0

MAX_PASSWORD_LENGTH = 256
DEFAULT_PASSWORD_LENGTH = 15

# ── Character sets ────────────────────────────────────────────────────────────
A_UPPER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A_UPPERC = "BCDFGHJKLMNPQRSTVWXYZ"
A_UPPERV = "AEIOU"
A_LOWER  = "abcdefghijklmnopqrstuvwxyz"
A_LOWERC = "bcdfghjklmnpqrstvwxyz"
A_LOWERV = "aeiou"
A_DIGIT  = "0123456789"
A_SYMBL  = "!@#$%^&*()-+;:,."
A_ALL    = A_UPPER + A_LOWER + A_DIGIT + A_SYMBL
A_FSTR   = "ulcvCVdsr"

FORMAT_MAP = {
    'u': A_UPPER,
    'l': A_LOWER,
    'c': A_LOWERC,
    'v': A_LOWERV,
    'C': A_UPPERC,
    'V': A_UPPERV,
    'd': A_DIGIT,
    's': A_SYMBL,
    'r': A_ALL,
}

# ── Random ────────────────────────────────────────────────────────────────────
def pw_rand(upper_bound: int) -> int:
    """Return a cryptographically secure uniform random int in [0, upper_bound)."""
    return secrets.randbelow(upper_bound)

# ── Generation ────────────────────────────────────────────────────────────────
def generate_random_password(length: int) -> str:
    return ''.join(secrets.choice(A_ALL) for _ in range(length))

def generate_from_format(fmt: str) -> str:
    return ''.join(secrets.choice(FORMAT_MAP[ch]) for ch in fmt)

# ── Password → format string ──────────────────────────────────────────────────
def password_to_format(password: str, specific: bool) -> str:
    result = []
    for ch in password:
        if ch.isdigit():
            result.append('d')
        elif ch in A_SYMBL:
            result.append('s')
        elif ch.isupper():
            if specific:
                result.append('V' if ch in A_UPPERV else 'C')
            else:
                result.append('u')
        elif ch.islower():
            if specific:
                result.append('v' if ch in A_LOWERV else 'c')
            else:
                result.append('l')
        else:
            result.append('r')
    return ''.join(result)

# ── Output helpers ────────────────────────────────────────────────────────────
def to_hex(s: str, upper: bool = False) -> str:
    fmt = '{:02X}' if upper else '{:02x}'
    return ''.join(fmt.format(b) for b in s.encode('latin-1', errors='replace'))

def print_with_hex(s: str, mode: str) -> None:
    """mode: '' | 'h' | 'H' | 'h0' | 'H0'"""
    if mode in ('h', 'H'):
        print(s)
    if mode in ('h', 'H', 'h0', 'H0'):
        print(to_hex(s, upper=(mode in ('H', 'H0'))))
    if mode == '':
        print(s)

def build_json_obj(s: str) -> dict:
    return {"password": s, "hex": to_hex(s)}

def print_json(passwords: list) -> None:
    if len(passwords) == 1:
        print(json.dumps(build_json_obj(passwords[0]), indent=2))
    else:
        print(json.dumps([build_json_obj(p) for p in passwords], indent=2))

# ── Validation ────────────────────────────────────────────────────────────────
def validate_format(fmt: str) -> None:
    if len(fmt) > MAX_PASSWORD_LENGTH:
        die(f"ERROR: Format string must be {MAX_PASSWORD_LENGTH} characters or less!")
    for i, ch in enumerate(fmt):
        if ch not in A_FSTR:
            die(f"ERROR: Invalid character '{ch}' at position {i + 1}!")

def parse_positive_int(s: str) -> int | None:
    try:
        v = int(s)
        if 1 <= v <= MAX_PASSWORD_LENGTH:
            return v
    except (ValueError, TypeError):
        pass
    return None

def parse_hex_mode(s: str) -> str | None:
    return s if s in ('h', 'H', 'h0', 'H0') else None

def parse_json_mode(s: str) -> bool:
    return s == 'j'

# ── Help / version ────────────────────────────────────────────────────────────
def version() -> None:
    print(f"ospwgen.py - Version {VER:04x} Revision {REV:02x}")
    print("©2022-2026 by billy@slack.net")
    print("https://github.com/D1A881/ospwgen")
    sys.exit(0)

def usage(cmd: str) -> None:
    print(f"Usage: {cmd} <format> [count] [h|H|h0|H0|j]")
    print(f"       {cmd} R [length] [count] [h|H|h0|H0|j]")
    print(f"       {cmd} F <password>")
    print(f"       {cmd} FS <password>")
    print(f"       {cmd} --help")
    sys.exit(0)

def help_(cmd: str) -> None:
    print(",-. ,-. ;-. , , , ,-: ,-. ;-.")
    print("| | `-. | | |/|/  | | |-' | |")
    print("`-' `-' |-' ' '   `-| `-' ' '")
    print("        '         `-'        ")
    print(f"Usage: {cmd} <format> [count] [h|H|h0|H0|j]\n")
    print("Format string characters:")
    print(" u = uppercase letter")
    print(" l = lowercase letter")
    print(" c = consonant")
    print(" v = vowel")
    print(" C = uppercase consonant")
    print(" V = uppercase vowel")
    print(" d = digit")
    print(" s = symbol")
    print(" r = random printable character\n")
    print("Optional second argument:")
    print(" count = Generate <count> passwords\n")
    print("Options [h|H|h0|H0|j]:")
    print(" h  = show output in hex also")
    print(" H  = show output in uppercase hex also")
    print(" h0 = show output in hex only")
    print(" H0 = show output in uppercase hex only")
    print(" j  = show output as JSON\n")
    print("Random passwords:")
    print(f" {cmd} R [length] [count] [h|H|h0|H0|j]")
    print(f" {cmd} R <n> = password of <n> length")
    print(f" {cmd} R <n1> <n2> = <n2> passwords of <n1> length\n")
    print("Password to format string:")
    print(f" {cmd} F <password>")
    print("  Converts each character of <password> to its format specifier.")
    print(f" {cmd} FS <password>")
    print("  Like F, but differentiates consonant/vowel within each case:\n"
          "   C = uppercase consonant, V = uppercase vowel\n"
          "   c = lowercase consonant, v = lowercase vowel\n")
    print("Misc options:")
    print(" -h/--help, prints this page")
    print(" -v/--version, prints version information")
    print("_____________________________________________\n")
    print(f"  Old School Password Generator - v{VER:04x} r{REV:02x}")
    print("         ©2022-2026 by billy@slack.net       ")
    print("       https://github.com/D1A881/ospwgen     ")
    print("_____________________________________________")
    sys.exit(0)

def die(msg: str) -> None:
    print(msg)
    sys.exit(1)

# ── Modes ─────────────────────────────────────────────────────────────────────
def handle_random_mode(args: list, cmd: str) -> None:
    length   = DEFAULT_PASSWORD_LENGTH
    count    = 1
    hexmode  = ''
    jsonmode = False

    if len(args) >= 1:
        v = parse_positive_int(args[0])
        if v is not None:
            length = v
        elif parse_hex_mode(args[0]):
            hexmode = parse_hex_mode(args[0])
        elif parse_json_mode(args[0]):
            jsonmode = True
        else:
            die(f"ERROR: Integer arguments must be between 1 and {MAX_PASSWORD_LENGTH}")

    if len(args) >= 2:
        v = parse_positive_int(args[1])
        if v is not None:
            count = v
        elif parse_hex_mode(args[1]):
            hexmode = parse_hex_mode(args[1])
        elif parse_json_mode(args[1]):
            jsonmode = True
        else:
            die(f"ERROR: Integer arguments must be between 1 and {MAX_PASSWORD_LENGTH}")

    if len(args) >= 3:
        if parse_json_mode(args[2]):
            jsonmode = True
        else:
            m = parse_hex_mode(args[2])
            if m:
                hexmode = m

    passwords = [generate_random_password(length) for _ in range(count)]
    if jsonmode:
        print_json(passwords)
    else:
        for p in passwords:
            print_with_hex(p, hexmode)

def handle_format_mode(fmt: str, args: list, cmd: str) -> None:
    validate_format(fmt)

    hexmode  = ''
    jsonmode = False
    count    = 1

    if args:
        v = parse_positive_int(args[0])
        if v is not None:
            count = v
            if len(args) >= 2:
                if parse_json_mode(args[1]):
                    jsonmode = True
                else:
                    m = parse_hex_mode(args[1])
                    if m:
                        hexmode = m
        elif parse_json_mode(args[0]):
            jsonmode = True
        else:
            m = parse_hex_mode(args[0])
            if m:
                hexmode = m

    passwords = [generate_from_format(fmt) for _ in range(count)]
    if jsonmode:
        print_json(passwords)
    else:
        for p in passwords:
            print_with_hex(p, hexmode)

# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    argv = sys.argv
    cmd  = argv[0]
    args = argv[1:]

    if not args:
        print("ERROR: Format string required!")
        usage(cmd)

    if args[0] in ('--help', '-h'):
        help_(cmd)

    if args[0] in ('--version', '-v'):
        version()

    if args[0] == 'R':
        handle_random_mode(args[1:], cmd)
        return

    if args[0] in ('F', 'FS'):
        specific = (args[0] == 'FS')
        if len(args) < 2:
            die("ERROR: Password required!")
        pw = args[1]
        if not pw:
            die("ERROR: Password must not be empty!")
        if len(pw) > MAX_PASSWORD_LENGTH:
            die(f"ERROR: Password must be {MAX_PASSWORD_LENGTH} characters or less!")
        print(password_to_format(pw, specific))
        return

    handle_format_mode(args[0], args[1:], cmd)

if __name__ == '__main__':
    main()
