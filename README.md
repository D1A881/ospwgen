# ospwgen GUI

**Old School Password Generator — GUI Edition** — A Tkinter front end for [ospwgen](https://github.com/D1A881/ospwgen), the pattern-based / random password generator. Same generation logic as the original C tool, reimplemented in pure Python and wrapped in a tabbed desktop interface.

```
,-. ,-. ;-. , , , ,-: ,-. ;-.
| | `-. | | |/|/  | | |-' | |
`-' `-' |-' ' '   `-| `-' ' '
        '         `-'
```

[![License: GPLv2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/language-Python%203-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#requirements)
[![GUI](https://img.shields.io/badge/interface-Tkinter-orange.svg)](https://docs.python.org/3/library/tkinter.html)

## What this is

`ospwgen_gui.py` is a single-file Tkinter application that gives the [original ospwgen.c](https://github.com/D1A881/ospwgen/blob/main/ospwgen.c) CLI tool a point-and-click interface. It reproduces the same three modes — pattern generation, random generation, and password analysis — and adds a couple of GUI-native conveniences (live results panel, copy/save, an editable delimiter between batch-generated passwords).

It's a derivative front end, not the official project. All credit for the original algorithm and character sets goes to the upstream author; see [License](#license) and [Credits](#credits).

## Features

- **Pattern-based generation** — Build a format string from `u l c v C V d s r` either by typing or clicking labeled buttons (hover for a tooltip on each)
- **Pure random mode** — Generate fully random passwords of any length (1–256 characters)
- **Password analysis** — Convert an existing password into its format string (`F` and `FS` equivalents), with a show/hide toggle on the password field
- **Multiple output formats** — Plain text, lowercase/uppercase hex (shown alongside or hex-only), or JSON
- **Batch generation** — Generate up to 1000 passwords per click
- **Editable delimiter** — Choose how multiple results are separated (newline, tab, comma, `---`, or any literal text) on both the Format and Random tabs
- **Cryptographically secure** — Uses Python's [`secrets`](https://docs.python.org/3/library/secrets.html) module (CSPRNG), the standard-library equivalent of `arc4random_uniform()` / `/dev/urandom`
- **Zero external dependencies** — Only the Python standard library (`tkinter`, `secrets`, `json`)
- **Cross-platform** — Runs anywhere Python 3 + Tk is available: Linux, macOS, Windows
- **Copy / save / clear** — One-click copy of results to the clipboard, save to a text file, or clear the panel

## Requirements

- Python 3.8 or later
- Tkinter (bundled with most Python installs; see notes below if it's missing)

```bash
# Debian/Ubuntu — Tkinter is sometimes a separate package
sudo apt-get install python3-tk

# Fedora
sudo dnf install python3-tkinter

# macOS / Windows — Tkinter ships with the official python.org installer
```

## Quick Start

```bash
# Just run it — no install, no pip packages
python3 ospwgen_gui.py
```

The window opens with a tab bar on the left (**Format Generator**, **Random Generator**, **Analyze (F/FS)**, **Help / About**) and a shared **Results** panel on the right.

## Using the GUI

### Format Generator tab

Equivalent of `ospwgen <format> [count] [output_mode]`.

1. Type a pattern into the **Pattern** field, or build one by clicking the `u l c v C V d s r` buttons (each shows what it inserts on hover).
2. Set **Count** to generate more than one password at once.
3. Pick an **Output format** (see [Output Formats](#output-formats) below).
4. If generating more than one, set the **Delimiter between passwords**.
5. Click **Generate** — results appear in the panel on the right.

| Character | Description | Example Output |
|-----------|---------------------------|----------------|
| `u`       | Uppercase letter          | `A`, `Z`, `M`  |
| `l`       | Lowercase letter          | `a`, `z`, `m`  |
| `c`       | Lowercase consonant       | `b`, `t`, `w`  |
| `v`       | Lowercase vowel           | `a`, `e`, `o`  |
| `C`       | Uppercase consonant       | `B`, `T`, `W`  |
| `V`       | Uppercase vowel           | `A`, `E`, `O`  |
| `d`       | Digit (0–9)               | `0`, `5`, `9`  |
| `s`       | Symbol                    | `!`, `@`, `+`  |
| `r`       | Random printable character| any of the above |

**Symbol set:** `!@#$%^&*()-+;:,.`

### Random Generator tab

Equivalent of `ospwgen R [length] [count] [output_mode]`.

1. Set **Length** (1–256) and **Count**.
2. Pick an **Output format**.
3. Set the **Delimiter between passwords** if generating more than one.
4. Click **Generate**.

Characters are drawn uniformly from the full set: `A-Z a-z 0-9 !@#$%^&*()-+;:,.`

### Analyze (F/FS) tab

Equivalent of `ospwgen F <password>` / `ospwgen FS <password>`.

1. Type (or paste) a password into the **Password** field. Check **Show** to reveal it, since it's masked by default.
2. Check **FS mode** to distinguish consonant/vowel within each case (`C`/`V`/`c`/`v`); leave unchecked for the broad classification (`u`/`l`).
3. Click **Analyze** — the panel shows the password's length and its format string.

**Broad (`F`) mapping:**

| Input character | Format output |
|---|:---:|
| `A–Z` | `u` |
| `a–z` | `l` |
| `0–9` | `d` |
| Symbol (`!@#$%^&*()-+;:,.`) | `s` |
| Any other printable | `r` |

**Specific (`FS`) mapping:**

| Input character | Format output |
|---|:---:|
| Uppercase consonant | `C` |
| Uppercase vowel (`A E I O U`) | `V` |
| Lowercase consonant | `c` |
| Lowercase vowel (`a e i o u`) | `v` |
| `0–9` | `d` |
| Symbol | `s` |
| Any other printable | `r` |

The resulting format string can be fed straight back into the **Format Generator** tab to produce new passwords with the same structure.

### Help / About tab

Reproduces the original CLI's ASCII banner and a quick reference of format characters and output options — useful if you forget a character without leaving the app.

## Output Formats

Available as radio buttons on the Format and Random tabs:

| Option | Equivalent CLI flag | Behavior |
|---|---|---|
| Plain text | *(none)* | Password only |
| Plain + lowercase hex (h) | `h` | Password, then its lowercase hex encoding |
| Plain + UPPERCASE hex (H) | `H` | Password, then its uppercase hex encoding |
| Hex only, lowercase (h0) | `h0` | Lowercase hex only |
| Hex only, UPPERCASE (H0) | `H0` | Uppercase hex only |
| JSON (j) | `j` | `{"password": "...", "hex": "..."}`, or a JSON array if count > 1 |

### Delimiter between passwords

New in the GUI: when generating more than one password (and not using JSON), you choose how results are joined:

- `\n` (default) — one per line
- `\t` — tab-separated
- `\r` — carriage return
- any literal text — e.g. `, ` or `---` or a custom separator

This has no effect in JSON mode, since JSON output is already a single structured value.

## Security

- Randomness comes from Python's `secrets` module, which uses the OS's CSPRNG (`os.urandom` under the hood) — the same security property as the original's `arc4random_uniform()` / `/dev/urandom` fallback, without needing platform-specific `#ifdef`s.
- All character selection is uniform over the relevant set; no modulo bias.
- Passwords typed into the **Analyze** tab are masked by default (toggle **Show** to reveal).

### Best Practices

- Use at least 12–15 characters for general-purpose passwords
- Include multiple character types (upper, lower, digits, symbols)
- Prefer the **Random Generator** tab for maximum entropy
- Avoid predictable patterns like `dddd` or `llll`
- Store generated passwords in a password manager
- Use unique passwords per service

## Differences from the CLI version

| Aspect | CLI (`ospwgen.c`) | This GUI |
|---|---|---|
| Interface | Command-line arguments | Tkinter tabs + buttons |
| Language | C | Python 3 (standard library only) |
| RNG | `arc4random_uniform()` / `/dev/urandom` | `secrets` module |
| Delimiter between batch results | Always newline | Editable (newline, tab, custom text, etc.) |
| Help text | `--help` flag | Dedicated "Help / About" tab |
| Output | stdout | In-app results panel, with copy/save/clear |

The underlying generation rules, character sets, and format-string semantics are intentionally identical to the original, so a format string built in this GUI behaves the same as one passed to the CLI.

## Troubleshooting

```text
# ModuleNotFoundError: No module named 'tkinter'
# → Install your OS's Tk package (see Requirements above), then re-run.

# Window opens but buttons look unstyled
# → The app tries the 'clam' ttk theme automatically; if it's unavailable on
#   your system, Tk falls back to its default theme — purely cosmetic.
```

## License

This GUI is a derivative work based on [ospwgen.c](https://github.com/D1A881/ospwgen/blob/main/ospwgen.c), Copyright ©2022-2026 [billy@slack.net](mailto:billy@slack.net), released under the GNU GPLv2 License. See [LICENSE](LICENSE) for details.

## Credits

- **Original algorithm, format-string design, and character sets**: [billy@slack.net](mailto:billy@slack.net) — [D1A881/ospwgen](https://github.com/D1A881/ospwgen)
- **Tkinter front end**: this repository

## Links

- **Upstream repository**: <https://github.com/D1A881/ospwgen>
- **Upstream issues**: <https://github.com/D1A881/ospwgen/issues>

---

**⚠️ Security Notice**: While this tool generates cryptographically secure passwords, proper password security also requires secure storage, transmission, and usage practices. Use a password manager and enable 2FA where possible.
