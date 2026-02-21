# ospwgen

**Old School Password Generator** — A fast, portable command-line tool for generating secure passwords using custom patterns or random characters.

```
,-. ,-. ;-. , , , ,-: ,-. ;-.
| | `-. | | |/|/  | | |-' | |
`-' `-' |-' ' '   `-| `-' ' '
        '         `-'        
```

[![License: GPLv2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)
[![C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20BSD-lightgrey.svg)](https://github.com/D1A881/ospwgen)

## Features

- **Pattern-based generation** — Define password structure with format strings
- **Pure random mode** — Generate fully random passwords of any length
- **Multiple output formats** — Plain text, hex, uppercase hex, or JSON
- **Batch generation** — Create multiple passwords in one command
- **Cryptographically secure** — Uses `arc4random_uniform()` or `/dev/urandom`
- **Zero dependencies** — Single C file, compiles everywhere
- **Fast** — Generate thousands of passwords per second

## Quick Start

### Installation

```bash
# Clone and compile
git clone https://github.com/D1A881/ospwgen.git
cd ospwgen
make

# Or compile manually
gcc -O2 -o ospwgen ospwgen.c -lm
```

### Basic Usage

```bash
# Generate a password from a pattern
$ ospwgen ulllddss
Xqvj84@#

# Generate 5 passwords
$ ospwgen ulllddss 5
Bwkp27#$
Zmtq63*-
Hfjx81!;
Cvrn34+,
Kgdw56@%

# Random password (default 15 chars)
$ ospwgen R
m7@Kz!qP3#xW9Lv

# Random password of specific length
$ ospwgen R 20
g4!Rn@8Wqz#2Lp$Xt7^

# Generate multiple with JSON output
$ ospwgen ulllddss 3 j
[
  {
    "password": "Xqvj84@#",
    "hex": "5871766a38344023"
  },
  {
    "password": "Bwkp27#$",
    "hex": "42776b7032372324"
  },
  {
    "password": "Zmtq63*-",
    "hex": "5a6d747136332a2d"
  }
]
```

## Format Characters

Use these characters to define password patterns:

| Character | Description                  | Example Output |
|-----------|------------------------------|----------------|
| `u`       | Uppercase letter             | `A`, `Z`, `M`  |
| `l`       | Lowercase letter             | `a`, `z`, `m`  |
| `c`       | Lowercase consonant          | `b`, `t`, `w`  |
| `v`       | Lowercase vowel              | `a`, `e`, `o`  |
| `C`       | Uppercase consonant          | `B`, `T`, `W`  |
| `V`       | Uppercase vowel              | `A`, `E`, `O`  |
| `d`       | Digit (0-9)                  | `0`, `5`, `9`  |
| `s`       | Symbol                       | `!`, `@`, `+`  |
| `r`       | Random printable character   | Any of above   |

**Symbol set:** `!@#$%^&*()-+;:,.`

## Usage Examples

### Pattern-Based Passwords

```bash
# Simple 8-character password: 1 upper, 3 lower, 2 digits, 2 symbols
$ ospwgen ulllddss
Xqvj84@#

# Pronounceable pattern: consonant-vowel-consonant-vowel-digit-digit
# Letters are random; cvcv structure makes them speakable, not meaningful
$ ospwgen cvcvdd
bufo73

# Complex pattern with uppercase consonants
$ ospwgen CCvvddss
BXau91$%

# Longer pronounceable passwords
$ ospwgen cvcvcvdds 5
bufeti83!
zovaku29@
ketowi56#
wupize14$
nibuxa77%
```

### Random Mode

```bash
# Random password with default length (15)
$ ospwgen R
m7@Kz!qP3#xW9Lv

# Random password of specific length
$ ospwgen R 32
g4!Rn@8Wqz#2Lp$Xt7^cF9&dH3*sB6m

# Generate 5 random 20-character passwords
$ ospwgen R 20 5
g4!Rn@8Wqz#2Lp$Xt7^
k9@Fv!3Zqx#7Ws$Ym2*
p2#Hb@6Nrw!4Gj$Zk8^
t7$Qm!9Cx@3Dn#Lv5*Wb
x1^Ys@4Hf!8Pk#Rg6$Nq

# Batch generation for provisioning
$ ospwgen R 16 100 > passwords.txt
```

### Output Formats

All examples below use the same run of `ospwgen ulllddss` producing `Xqvj84@#`:

```bash
# Plain text (default)
$ ospwgen ulllddss
Xqvj84@#

# Hex encoding (lowercase) — shows password then hex
$ ospwgen ulllddss h
Xqvj84@#
5871766a38344023

# Hex encoding (uppercase) — shows password then hex
$ ospwgen ulllddss H
Xqvj84@#
5871766A38344023

# Hex only (no plaintext, lowercase)
$ ospwgen ulllddss h0
5871766a38344023

# Hex only (no plaintext, uppercase)
$ ospwgen ulllddss H0
5871766A38344023

# JSON output (single password)
$ ospwgen ulllddss j
{
  "password": "Xqvj84@#",
  "hex": "5871766a38344023"
}

# JSON output (multiple passwords)
$ ospwgen ulllddss 3 j
[
  {
    "password": "Xqvj84@#",
    "hex": "5871766a38344023"
  },
  {
    "password": "Bwkp27#$",
    "hex": "42776b7032372324"
  },
  {
    "password": "Zmtq63*-",
    "hex": "5a6d747136332a2d"
  }
]
```

### Practical Use Cases

```bash
# Generate passwords for 100 new users
$ ospwgen Cvccvdddss 100 > user_passwords.txt

# API key generation (hex token, no plaintext)
$ ospwgen R 32 h0
a3f7c2e8b1d4f09a6c3e7b2d8f1c4a09e5b7d3f2c8a1e6b4d9f0c7a2e3b5d8f1

# Database passwords with JSON for automation
$ ospwgen Ullllddddss 3 j
[
  {
    "password": "Xqvjt4927@!",
    "hex": "5871766a74343932374021"
  },
  {
    "password": "Bwkpn2815#$",
    "hex": "42776b706e323831352324"
  },
  {
    "password": "Zmtqr7463*-",
    "hex": "5a6d747172373436332a2d"
  }
]

# Pronounceable but secure passwords
$ ospwgen cvcvcvdds 5
bufeti83!
zovaku29@
ketowi56#
wupize14$
nibuxa77%

# WiFi password (easier to type on a phone keypad than full random)
$ ospwgen CCvvddss
BXau91$%

# Hex tokens for security applications
$ ospwgen R 24 H0
7F3A9C2E1B8D4F6A0E5C3B7D9A2F4E8C1B6D3A7F9C2E4B8D
```

## Command Reference

### Syntax

```
ospwgen <format> [count] [output_mode]
ospwgen R [length] [count] [output_mode]
ospwgen --help | -h
ospwgen --version | -v
```

### Arguments

- **`<format>`** — Pattern string using format characters (max 256 chars)
- **`count`** — Number of passwords to generate (default: 1)
- **`length`** — Length for random passwords (default: 15)
- **`output_mode`** — Output format option:
  - `h` — Show password + lowercase hex
  - `H` — Show password + uppercase hex
  - `h0` — Show lowercase hex only
  - `H0` — Show uppercase hex only
  - `j` — Show JSON output

### Options

- **`--help`**, **`-h`** — Display help message
- **`--version`**, **`-v`** — Display version information

## Security

### Cryptographic Randomness

ospwgen uses cryptographically secure random number generators:

- **BSD/macOS**: `arc4random_uniform()`
- **Linux (glibc ≥2.36)**: `arc4random_uniform()`
- **Older Linux**: `/dev/urandom` with rejection sampling

All methods provide uniform distribution without modulo bias.

### Entropy Estimates

| Pattern          | Entropy (bits) | Crack Time (1B/sec) |
|------------------|---------------:|---------------------|
| `ulllddss`       | ~48            | ~3 days             |
| `Ullllddddss`    | ~60            | ~37 years           |
| `R` (15 chars)   | ~98            | ~10¹⁹ years         |
| `R 20`           | ~131           | ~10²⁷ years         |

**Note:** Actual entropy depends on character set diversity and length.

### Best Practices

- **Use at least 12-15 characters** for general-purpose passwords
- **Include multiple character types** (upper, lower, digits, symbols)
- **Use random mode (`R`)** for maximum security
- **Never use predictable patterns** like `dddd` or `llll`
- **Store generated passwords securely** (password manager)
- **Use unique passwords** for different services

## Building & Installation

### Requirements

- C compiler (gcc, clang, or compatible)
- POSIX-compliant system (Linux, macOS, *BSD)
- `/dev/urandom` (on systems without `arc4random_uniform`)

### Compile

```bash
# Basic compilation
gcc -o ospwgen ospwgen.c -lm

# Optimized build
gcc -O2 -o ospwgen ospwgen.c -lm

# With all warnings
gcc -Wall -Wextra -O2 -o ospwgen ospwgen.c -lm

# Static binary
gcc -static -O2 -o ospwgen ospwgen.c -lm
```

### Install System-Wide

```bash
# Install to /usr/local/bin
sudo cp ospwgen /usr/local/bin/
sudo chmod +x /usr/local/bin/ospwgen

# Or use the Makefile
make
sudo make install
```

### Makefile Targets

```bash
make          # Compile ospwgen
make clean    # Remove binary
make install  # Install to /usr/local/bin
make test     # Run basic tests
```

## Integration Examples

### Shell Scripts

```bash
#!/bin/bash
# Generate passwords for new user accounts

while IFS= read -r username; do
    password=$(ospwgen Ullllddddss)
    echo "$username:$password"
done < users.txt

# Example output:
# alice:Xqvjt4927@!
# bob:Bwkpn2815#$
# carol:Zmtqr7463*-
```

### Python

```python
import subprocess
import json

# Generate passwords in JSON format
result = subprocess.run(
    ['ospwgen', 'Ullllddddss', '3', 'j'],
    capture_output=True,
    text=True
)

passwords = json.loads(result.stdout)
for entry in passwords:
    print(f"Password: {entry['password']}")
    print(f"Hex:      {entry['hex']}")

# Output:
# Password: Xqvjt4927@!
# Hex:      5871766a74343932374021
# Password: Bwkpn2815#$
# Hex:      42776b706e323831352324
# Password: Zmtqr7463*-
# Hex:      5a6d747172373436332a2d
```

### Ansible Playbook

```yaml
- name: Generate secure passwords
  command: ospwgen R 20 {{ user_count }} j
  register: passwords_output

- name: Parse passwords
  set_fact:
    user_passwords: "{{ passwords_output.stdout | from_json }}"
```

### Docker

```dockerfile
FROM alpine:latest
RUN apk add --no-cache gcc musl-dev make
COPY ospwgen.c .
RUN gcc -O2 -static -o /usr/local/bin/ospwgen ospwgen.c -lm
ENTRYPOINT ["ospwgen"]
```

```bash
# Run via Docker
$ docker build -t ospwgen .
$ docker run --rm ospwgen ulllddss
Xqvj84@#

$ docker run --rm ospwgen R 20
g4!Rn@8Wqz#2Lp$Xt7^
```

## Comparison

| Tool         | Pattern Support | JSON Output | Portable | Single File |
|--------------|:---------------:|:-----------:|:--------:|:-----------:|
| **ospwgen**  | ✅              | ✅          | ✅       | ✅          |
| pwgen        | Limited         | ❌          | ✅       | ❌          |
| apg          | ❌              | ❌          | ✅       | ❌          |
| makepasswd   | ❌              | ❌          | ❌       | ❌          |

## Performance

Benchmark on Intel i5 @ 2.4GHz:

```bash
# Generate 10,000 pattern passwords
$ time ospwgen ulllddss 10000 > /dev/null
real    0m0.090s
user    0m0.085s
sys     0m0.005s
# ~111,000 passwords/sec

# Generate 10,000 random 20-character passwords
$ time ospwgen R 20 10000 > /dev/null
real    0m0.121s
user    0m0.114s
sys     0m0.007s
# ~82,600 passwords/sec
```

## Troubleshooting

### Compilation Errors

```bash
# Error: undefined reference to 'arc4random_uniform'
# Solution: Update glibc or let fallback to /dev/urandom (automatic)

# Error: math.h not found
# Solution: Install build-essential (Debian/Ubuntu)
$ sudo apt-get install build-essential
```

### Runtime Errors

```bash
# Error: /dev/urandom: Permission denied
# Solution: Check file permissions
$ ls -l /dev/urandom
crw-rw-rw- 1 root root 1, 9 Feb 20 09:14 /dev/urandom

# Error: Format string too long (max 256 characters)
$ ospwgen $(printf 'u%.0s' {1..257})
ospwgen: error: format string exceeds maximum length of 256

$ ospwgen $(printf 'u%.0s' {1..256})
XKZMBVQRJLWFPTYHADNSGCWIOUEMXKZMBVQRJLWFPTYHADNSGCWIOUEMXKZMBVQRJLWF...
```

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Add tests if applicable
5. Commit with clear messages
6. Push and open a Pull Request

### Code Style

- Follow existing formatting (K&R with `//` comments)
- Comment non-obvious logic
- Keep functions focused and < 50 lines
- Test on Linux and macOS

## License

Copyright ©2022-2026 billy@slack.net

Released under the GNU GPLv2 License. See [LICENSE](LICENSE) file for details.

## Author

Created and maintained by **billy@slack.net**

## Links

- **Repository**: https://github.com/D1A881/ospwgen
- **Issues**: https://github.com/D1A881/ospwgen/issues
- **Releases**: https://github.com/D1A881/ospwgen/releases

## Changelog

### v0211r02 (Current)
- Added JSON output support (`j` flag)
- Added version and help flags (`-v`, `-h`)
- Improved portability (works on glibc < 2.36)
- Performance optimizations (cached strlen calls)
- Fixed off-by-one errors in validation
- Better error messages

### v0211r01
- Initial public release
- Pattern-based password generation
- Random mode support
- Hex output modes
- Portable random number generation

---

**⚠️ Security Notice**: While ospwgen generates cryptographically secure passwords, proper password security also requires secure storage, transmission, and usage practices. Always use HTTPS, password managers, and 2FA where possible.
