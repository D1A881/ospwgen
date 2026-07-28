#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//Portable Random
//pw_rand(upper_bound) - returns uniform random in [0, upper_bound)
//Uses arc4random_uniform when available, /dev/urandom otherwise

static uint32_t pw_rand(uint32_t upper_bound) {
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__APPLE__) || \
    (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 36)))
    return arc4random_uniform(upper_bound);
#else
    static FILE *urandom_fp = NULL;

    if (upper_bound < 2) return 0;

    if (!urandom_fp) {
        urandom_fp = fopen("/dev/urandom", "rb");
        if (!urandom_fp) { perror("fopen /dev/urandom"); exit(1); }
    }

    //Rejection sampling to avoid modulo bias.
    uint32_t min = (-upper_bound) % upper_bound;
    uint32_t r;
    do {
        if (fread(&r, sizeof(r), 1, urandom_fp) != 1) {
            perror("fread");
            fclose(urandom_fp);
            exit(1);
        }
    } while (r < min);
    return r % upper_bound;
#endif
}

#define VER 0x0216
#define REV 0
#define MAX_PASSWORD_LENGTH 256
#define MAX_COUNT 100000
#define DEFAULT_PASSWORD_LENGTH 15

//Character sets
static const char a_upper[]  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char a_upperc[] = "BCDFGHJKLMNPQRSTVWXYZ";
static const char a_upperv[] = "AEIOU";
static const char a_lower[]  = "abcdefghijklmnopqrstuvwxyz";
static const char a_lowerc[] = "bcdfghjklmnpqrstvwxyz";
static const char a_lowerv[] = "aeiou";
static const char a_digit[]  = "0123456789";
static const char a_symbl[]  = "!@#$%^&*()-+;:,.";
static const char a_all[]    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-+;:,.";
static const char a_fstr[]   = "ulcvCVdsr";

typedef enum {
    HEX_NONE,
    HEX_LOWER,
    HEX_UPPER,
    HEX_LOWER_ONLY,
    HEX_UPPER_ONLY
} hex_mode_t;

typedef enum {
    JSON_NONE,
    JSON_OUTPUT
} json_mode_t;

void version(void) {
    printf("ospwgen.c - Version %04x Revision %02x\n", VER, REV);
    printf("©2022-2026 by billy@slack.net\n");
    printf("https://github.com/D1A881/ospwgen\n");
}

void usage(const char *cmd) {
    printf("Usage: %s <format> [count] [h|H|h0|H0|j]\n", cmd);
    printf("       %s R [length] [count] [h|H|h0|H0|j]\n", cmd);
    printf("       %s F <password>\n", cmd);
    printf("       %s FS <password>\n", cmd);
    printf("       %s --help\n", cmd);
}

void help(const char *cmd) {
    printf(",-. ,-. ;-. , , , ,-: ,-. ;-.\n");
    printf("| | `-. | | |/|/  | | |-' | |\n");
    printf("`-' `-' |-' ' '   `-| `-' ' '\n");
    printf("        '         `-'        \n");
    printf("Usage: %s <format> [count] [h|H|h0|H0|j]\n\n", cmd);
    printf("Format string characters:\n");
    printf(" u = uppercase letter\n");
    printf(" l = lowercase letter\n");
    printf(" c = consonant\n");
    printf(" v = vowel\n");
    printf(" C = uppercase consonant\n");
    printf(" V = uppercase vowel\n");
    printf(" d = digit\n");
    printf(" s = symbol\n");
    printf(" r = random printable character\n\n");
    printf("Optional second argument:\n");
    printf(" count = Generate <count> passwords\n\n");
    printf("Options [h|H|h0|H0|j]:\n");
    printf(" h  = show output in hex also\n");
    printf(" H  = show output in uppercase hex also\n");
    printf(" h0 = show output in hex only\n");
    printf(" H0 = show output in uppercase hex only\n");
    printf(" j  = show output as JSON\n\n");
    printf("Random passwords:\n");
    printf(" %s R [length] [count] [h|H|h0|H0|j]\n", cmd);
    printf(" %s R <n> = password of <n> length\n", cmd);
    printf(" %s R <n1> <n2> = <n2> passwords of <n1> length\n\n", cmd);
    printf("Password to format string:\n");
    printf(" %s F <password>\n", cmd);
    printf(" Converts each character of <password> to its format specifier.\n");
    printf(" %s FS <password>\n", cmd);
    printf(" Like F, but differentiates consonant/vowel within each case:\n");
    printf("  C = uppercase consonant, V = uppercase vowel\n");
    printf("  c = lowercase consonant, v = lowercase vowel\n\n");
    printf("Misc options:\n");
    printf(" -h/--help, prints this page\n");
    printf(" -v/--version, prints version information\n");
    printf("_____________________________________________\n\n");
    printf("  Old School Password Generator - v%04x r%02x\n", VER, REV);
    printf("         ©2022-2026 by billy@slack.net       \n");
    printf("       https://github.com/D1A881/ospwgen     \n");
    printf("_____________________________________________\n");
}

//Parses a positive integer bounded by [1, max]. Returns 1 on success.
int parse_bounded_int(const char *s, int max, int *out) {
    char *end;
    long v;

    if (!s || *s == '\0') return 0;

    v = strtol(s, &end, 10);
    if (*end != '\0') return 0;
    if (v <= 0 || v > max) return 0;

    *out = (int)v;
    return 1;
}

int parse_length(const char *s, int *out) {
    return parse_bounded_int(s, MAX_PASSWORD_LENGTH, out);
}

int parse_count(const char *s, int *out) {
    return parse_bounded_int(s, MAX_COUNT, out);
}

//Returns 1 and sets *hexmode/*jsonmode if s is a recognized output-mode
//token ("h", "H", "h0", "H0", "j"). Returns 0 otherwise (s is not a mode
//token at all -- caller decides whether that's an error).
int try_parse_output_mode(const char *s, hex_mode_t *hexmode, json_mode_t *jsonmode) {
    if (!s) return 0;
    if (strcmp(s, "j") == 0)  { *jsonmode = JSON_OUTPUT; *hexmode = HEX_NONE;       return 1; }
    if (strcmp(s, "h") == 0)  { *hexmode  = HEX_LOWER;   *jsonmode = JSON_NONE;     return 1; }
    if (strcmp(s, "H") == 0)  { *hexmode  = HEX_UPPER;   *jsonmode = JSON_NONE;     return 1; }
    if (strcmp(s, "h0") == 0) { *hexmode  = HEX_LOWER_ONLY; *jsonmode = JSON_NONE;  return 1; }
    if (strcmp(s, "H0") == 0) { *hexmode  = HEX_UPPER_ONLY; *jsonmode = JSON_NONE;  return 1; }
    return 0;
}

//Validates and parses the output-mode argument at argv[idx], if present.
//If idx >= argc, output mode defaults to none (not an error).
//If idx < argc but the token isn't a recognized mode, prints an error and
//exits -- this closes the "silently ignore garbage trailing argument" hole.
void parse_output_mode_arg(int argc, char **argv, int idx,
                            hex_mode_t *hexmode, json_mode_t *jsonmode,
                            const char *cmd) {
    *hexmode = HEX_NONE;
    *jsonmode = JSON_NONE;

    if (idx >= argc) return;

    if (!try_parse_output_mode(argv[idx], hexmode, jsonmode)) {
        printf("ERROR: Invalid option '%s'! Expected one of h, H, h0, H0, j\n", argv[idx]);
        usage(cmd);
        exit(1);
    }
}

//Validation
void validate_format(const char *fmt, const char *cmd) {
    size_t len = strlen(fmt);

    if (len == 0) {
        printf("ERROR: Format string must not be empty!\n");
        usage(cmd);
        exit(1);
    }

    if (len > MAX_PASSWORD_LENGTH) {
        printf("ERROR: Format string must be %d characters or less!\n", MAX_PASSWORD_LENGTH);
        usage(cmd);
        exit(1);
    }

    for (size_t i = 0; i < len; i++) {
        if (!strchr(a_fstr, fmt[i])) {
            printf("ERROR: Invalid character '%c' at position %zu!\n", fmt[i], i + 1);
            usage(cmd);
            exit(1);
        }
    }
}

//Generation
void generate_random_password(char *out, int length) {
    int l_all = sizeof(a_all) - 1;
    for (int i = 0; i < length; i++) {
        out[i] = a_all[pw_rand((uint32_t)l_all)];
    }
    out[length] = '\0';
}

void generate_from_format(const char *fmt, char *out) {
    size_t len = strlen(fmt);

    for (size_t i = 0; i < len; i++) {
        switch (fmt[i]) {
        case 'u': out[i] = a_upper [pw_rand(sizeof(a_upper)  - 1)]; break;
        case 'l': out[i] = a_lower [pw_rand(sizeof(a_lower)  - 1)]; break;
        case 'c': out[i] = a_lowerc[pw_rand(sizeof(a_lowerc) - 1)]; break;
        case 'v': out[i] = a_lowerv[pw_rand(sizeof(a_lowerv) - 1)]; break;
        case 'C': out[i] = a_upperc[pw_rand(sizeof(a_upperc) - 1)]; break;
        case 'V': out[i] = a_upperv[pw_rand(sizeof(a_upperv) - 1)]; break;
        case 'd': out[i] = a_digit [pw_rand(sizeof(a_digit)  - 1)]; break;
        case 's': out[i] = a_symbl [pw_rand(sizeof(a_symbl)  - 1)]; break;
        case 'r': out[i] = a_all   [pw_rand(sizeof(a_all)    - 1)]; break;
        }
    }
    out[len] = '\0';
}

//Password to format string conversion
//Maps each character in the password to its format specifier.
//
//When specific == 0 (F mode):
//  uppercase letter        -> 'u'
//  lowercase letter        -> 'l'
//  digit                   -> 'd'
//  symbol (from a_symbl)   -> 's'
//  any other printable     -> 'r'
//
//When specific == 1 (FS mode), letters are further broken down by case and
//consonant/vowel using the same character sets as the generator:
//  uppercase consonant     -> 'C'
//  uppercase vowel         -> 'V'
//  lowercase consonant     -> 'c'
//  lowercase vowel         -> 'v'
//  digit                   -> 'd'
//  symbol (from a_symbl)   -> 's'
//  any other printable     -> 'r'
void password_to_format(const char *password, int specific, const char *cmd) {
    size_t len = strlen(password);

    if (len == 0) {
        printf("ERROR: Password must not be empty!\n");
        usage(cmd);
        exit(1);
    }

    if (len > MAX_PASSWORD_LENGTH) {
        printf("ERROR: Password must be %d characters or less!\n", MAX_PASSWORD_LENGTH);
        usage(cmd);
        exit(1);
    }

    for (size_t i = 0; i < len; i++) {
        char c = password[i];
        if (c >= '0' && c <= '9') {
            putchar('d');
        } else if (strchr(a_symbl, c)) {
            putchar('s');
        } else if (c >= 'A' && c <= 'Z') {
            if (specific) {
                putchar(strchr(a_upperv, c) ? 'V' : 'C');
            } else {
                putchar('u');
            }
        } else if (c >= 'a' && c <= 'z') {
            if (specific) {
                putchar(strchr(a_lowerv, c) ? 'v' : 'c');
            } else {
                putchar('l');
            }
        } else {
            putchar('r');
        }
    }
    putchar('\n');
}

//JSON helpers

//Escape a password string for safe JSON output.
//Characters that must be escaped inside a JSON string: \, ", and control chars.
void json_escape(const char *str, char *escaped, size_t escaped_size) {
    size_t j = 0;
    for (size_t i = 0; str[i] != '\0' && j + 2 < escaped_size; i++) {
        unsigned char c = (unsigned char)str[i];
        if (c == '\\' || c == '"') {
            escaped[j++] = '\\';
            escaped[j++] = (char)c;
        } else if (c < 0x20) {
            //Control characters: emit \uXXXX
            int written = snprintf(escaped + j, escaped_size - j, "\\u%04x", c);
            if (written < 0) break;
            j += (size_t)written;
        } else {
            escaped[j++] = (char)c;
        }
    }
    escaped[j] = '\0';
}

//Print a single password as a JSON object: {"password":"...", "hex":"..."}
//indent is prepended to each line so the same routine works standalone or
//nested inside a JSON array.
void print_json_entry(const char *str, const char *indent, int trailing_comma) {
    char escaped[MAX_PASSWORD_LENGTH * 6 + 1]; //worst case: every char -> \uXXXX
    json_escape(str, escaped, sizeof(escaped));

    printf("%s{\n", indent);
    printf("%s  \"password\": \"%s\",\n", indent, escaped);
    printf("%s  \"hex\": \"", indent);

    size_t len = strlen(str);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", (unsigned char)str[i]);
    }
    printf("\"\n");
    printf("%s}%s\n", indent, trailing_comma ? "," : "");
}

//Prints `count` passwords as JSON: a bare object if count == 1, otherwise
//a JSON array of objects.
void print_json_passwords(char passwords[][MAX_PASSWORD_LENGTH + 1], int count) {
    if (count == 1) {
        print_json_entry(passwords[0], "", 0);
        return;
    }

    printf("[\n");
    for (int i = 0; i < count; i++) {
        print_json_entry(passwords[i], "  ", i < count - 1);
    }
    printf("]\n");
}

//Output
void print_with_hex(const char *str, hex_mode_t mode) {
    if (mode == HEX_LOWER || mode == HEX_UPPER) {
        printf("%s\n", str);
    }

    if (mode != HEX_NONE) {
        size_t len = strlen(str);
        for (size_t i = 0; i < len; i++) {
            printf(
                (mode == HEX_UPPER || mode == HEX_UPPER_ONLY) ? "%X" : "%x",
                (unsigned char)str[i]
            );
        }
        printf("\n");
    }

    if (mode == HEX_NONE) {
        printf("%s\n", str);
    }
}

//Generates `count` passwords using `generator` (either a fixed-length
//random generator or a format-driven generator) and emits them either as
//plain/hex text or as JSON, depending on jsonmode/hexmode.
void emit_passwords(int count, hex_mode_t hexmode, json_mode_t jsonmode,
                     void (*generate)(void *ctx, char *out), void *ctx) {
    if (jsonmode == JSON_OUTPUT) {
        char (*passwords)[MAX_PASSWORD_LENGTH + 1] =
            malloc((size_t)count * sizeof(*passwords));
        if (!passwords) {
            fprintf(stderr, "ERROR: Out of memory\n");
            exit(1);
        }
        for (int i = 0; i < count; i++) {
            generate(ctx, passwords[i]);
        }
        print_json_passwords(passwords, count);
        free(passwords);
    } else {
        char out[MAX_PASSWORD_LENGTH + 1];
        for (int i = 0; i < count; i++) {
            generate(ctx, out);
            print_with_hex(out, hexmode);
        }
    }
}

typedef struct { int length; } random_ctx_t;
void generate_random_cb(void *ctx, char *out) {
    random_ctx_t *rc = (random_ctx_t *)ctx;
    generate_random_password(out, rc->length);
}

typedef struct { const char *fmt; } format_ctx_t;
void generate_format_cb(void *ctx, char *out) {
    format_ctx_t *fc = (format_ctx_t *)ctx;
    generate_from_format(fc->fmt, out);
}

//Random mode: ospwgen R [length] [count] [h|H|h0|H0|j]
//Any argument that isn't consumed as length/count and isn't a valid output
//mode token is a hard error -- nothing is silently ignored.
void handle_random_mode(int argc, char **argv, const char *cmd) {
    int length = DEFAULT_PASSWORD_LENGTH;
    int count  = 1;
    hex_mode_t hexmode;
    json_mode_t jsonmode;
    int next = 2;

    if (next < argc && parse_length(argv[next], &length)) {
        next++;
    } else if (next < argc && !try_parse_output_mode(argv[next], &hexmode, &jsonmode)) {
        printf("ERROR: Length must be an integer between 1 and %d\n", MAX_PASSWORD_LENGTH);
        usage(cmd);
        exit(1);
    }

    if (next < argc && parse_count(argv[next], &count)) {
        next++;
    } else if (next < argc && !try_parse_output_mode(argv[next], &hexmode, &jsonmode)) {
        printf("ERROR: Count must be an integer between 1 and %d\n", MAX_COUNT);
        usage(cmd);
        exit(1);
    }

    parse_output_mode_arg(argc, argv, next, &hexmode, &jsonmode, cmd);
    if (next + 1 < argc) {
        printf("ERROR: Too many arguments!\n");
        usage(cmd);
        exit(1);
    }

    random_ctx_t rc = { length };
    emit_passwords(count, hexmode, jsonmode, generate_random_cb, &rc);
    exit(0);
}

//
// entry point
//

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("ERROR: Format string required!\n");
        usage(argv[0]);
        exit(1);
    }

    if ((strcmp(argv[1], "--help") == 0) || (strcmp(argv[1], "-h") == 0)) {
        help(argv[0]);
        exit(0);
    }

    if ((strcmp(argv[1], "--version") == 0) || (strcmp(argv[1], "-v") == 0)) {
        version();
        exit(0);
    }

    if (strcmp(argv[1], "R") == 0) {
        handle_random_mode(argc, argv, argv[0]);
    }

    //FORMAT CONVERSION MODE: F <password>
    //Converts each character of the given password to its format specifier.
    //FS mode further differentiates uppercase/lowercase consonants and vowels.
    if (strcmp(argv[1], "F") == 0 || strcmp(argv[1], "FS") == 0) {
        int specific = (strcmp(argv[1], "FS") == 0) ? 1 : 0;
        if (argc < 3) {
            printf("ERROR: Password required!\n");
            usage(argv[0]);
            exit(1);
        }
        password_to_format(argv[2], specific, argv[0]);
        exit(0);
    }

    validate_format(argv[1], argv[0]);

    //FORMAT GENERATION MODE: ospwgen <format> [count] [h|H|h0|H0|j]
    int count = 1;
    hex_mode_t hexmode;
    json_mode_t jsonmode;
    int next = 2;

    if (next < argc && parse_count(argv[next], &count)) {
        next++;
    } else if (next < argc && !try_parse_output_mode(argv[next], &hexmode, &jsonmode)) {
        printf("ERROR: Count must be an integer between 1 and %d\n", MAX_COUNT);
        usage(argv[0]);
        exit(1);
    }

    parse_output_mode_arg(argc, argv, next, &hexmode, &jsonmode, argv[0]);
    if (next + 1 < argc) {
        printf("ERROR: Too many arguments!\n");
        usage(argv[0]);
        exit(1);
    }

    format_ctx_t fc = { argv[1] };
    emit_passwords(count, hexmode, jsonmode, generate_format_cb, &fc);

    return 0;
}
