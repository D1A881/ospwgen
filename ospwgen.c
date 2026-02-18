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
    if (upper_bound < 2) return 0;
    uint32_t min = (uint32_t)(-(int32_t)upper_bound) % upper_bound;
    uint32_t r;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) { perror("fopen /dev/urandom"); exit(1); }
    do {
        if (fread(&r, sizeof(r), 1, f) != 1) {
            perror("fread");
            fclose(f);
            exit(1);
        }
    } while (r < min);
    fclose(f);
    return r % upper_bound;
#endif
}

#define VER 0x0211
#define REV 2
#define MAX_PASSWORD_LENGTH 256
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
    exit(0);
}

void usage(const char *cmd) {
    printf("Usage: %s <format> [count] [h|H|h0|H0|j]\n", cmd);
    printf("       %s R [length] [count] [h|H|h0|H0|j]\n", cmd);
    printf("       %s --help\n", cmd);
    exit(0);
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
    printf("Misc options:\n");
    printf(" -h/--help, prints this page\n");
    printf(" -v/--version, prints version information\n");
    printf("_____________________________________________\n\n");
    printf("  Old School Password Generator - v%04x r%02x\n", VER, REV);
    printf("         ©2022-2026 by billy@slack.net       \n");
    printf("       https://github.com/D1A881/ospwgen     \n");
    printf("_____________________________________________\n");
    exit(0);
}

int parse_positive_int(const char *s, int *out) {
    char *end;
    long v;

    if (!s || *s == '\0') return 0;

    v = strtol(s, &end, 10);
    if (*end != '\0') return 0;
    if (v <= 0 || v > MAX_PASSWORD_LENGTH) return 0;

    *out = (int)v;
    return 1;
}

hex_mode_t parse_hex_mode(const char *s) {
    if (!s) return HEX_NONE;
    if (strcmp(s, "h")  == 0) return HEX_LOWER;
    if (strcmp(s, "H")  == 0) return HEX_UPPER;
    if (strcmp(s, "h0") == 0) return HEX_LOWER_ONLY;
    if (strcmp(s, "H0") == 0) return HEX_UPPER_ONLY;
    return HEX_NONE;
}

json_mode_t parse_json_mode(const char *s) {
    if (!s) return JSON_NONE;
    if (strcmp(s, "j") == 0) return JSON_OUTPUT;
    return JSON_NONE;
}

//Validation
void validate_format(const char *fmt, const char *cmd) {
    size_t len = strlen(fmt);

    if (len > MAX_PASSWORD_LENGTH) {
        printf("ERROR: Format string must be %d characters or less!\n", MAX_PASSWORD_LENGTH);
        usage(cmd);
    }

    for (size_t i = 0; i < len; i++) {
        if (!strchr(a_fstr, fmt[i])) {
            printf("ERROR: Invalid character '%c' at position %zu!\n", fmt[i], i + 1);
            usage(cmd);
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

//Print a single password as a JSON object:
//{"password":"...", "hex":"..."}
void print_json_single(const char *str) {
    char escaped[MAX_PASSWORD_LENGTH * 6 + 1]; //worst case: every char -> \uXXXX
    json_escape(str, escaped, sizeof(escaped));

    printf("{\n");
    printf("  \"password\": \"%s\",\n", escaped);
    printf("  \"hex\": \"");

    size_t len = strlen(str);  //cache strlen
    for (size_t i = 0; i < len; i++) {
        printf("%02x", (unsigned char)str[i]);
    }
    printf("\"\n");
    printf("}\n");
}

//Collect all passwords into a JSON array and print at once.
//Caller passes a pre-allocated array of strings and the count.
void print_json_array(const char passwords[][MAX_PASSWORD_LENGTH + 1], int count) {
    char escaped[MAX_PASSWORD_LENGTH * 6 + 1];

    printf("[\n");
    for (int i = 0; i < count; i++) {
        json_escape(passwords[i], escaped, sizeof(escaped));
        printf("  {\n");
        printf("    \"password\": \"%s\",\n", escaped);
        printf("    \"hex\": \"");

        size_t len = strlen(passwords[i]);  //cache strlen
        for (size_t k = 0; k < len; k++) {
            printf("%02x", (unsigned char)passwords[i][k]);
        }
        printf("\"\n");
        printf("  }%s\n", (i < count - 1) ? "," : "");
    }
    printf("]\n");
}

//Output
void print_with_hex(const char *str, hex_mode_t mode) {
    if (mode == HEX_LOWER || mode == HEX_UPPER) {
        printf("%s\n", str);
    }

    if (mode != HEX_NONE) {
        size_t len = strlen(str);  //cache strlen
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

//Random mode
void handle_random_mode(int argc, char **argv, char *out, const char *cmd) {
    int length = DEFAULT_PASSWORD_LENGTH;
    int count  = 1;
    int tmp;
    hex_mode_t hexmode   = HEX_NONE;
    json_mode_t jsonmode = JSON_NONE;

    //length
    if (argc >= 3 && parse_positive_int(argv[2], &tmp)) {
        length = tmp;
    }

    //count
    if (argc >= 4 && parse_positive_int(argv[3], &tmp)) {
        count = tmp;
    }

    //output mode option (hex or json)
    if (argc >= 5) {
        jsonmode = parse_json_mode(argv[4]);
        if (jsonmode == JSON_NONE) hexmode = parse_hex_mode(argv[4]);
    } else if (argc >= 4 && !parse_positive_int(argv[3], &tmp)) {
        jsonmode = parse_json_mode(argv[3]);
        if (jsonmode == JSON_NONE) hexmode = parse_hex_mode(argv[3]);
    }

    //Validate unexpected integer arguments
    if ((argc >= 3 && argv[2] && !parse_positive_int(argv[2], &tmp) && parse_hex_mode(argv[2]) == HEX_NONE && parse_json_mode(argv[2]) == JSON_NONE) ||
        (argc >= 4 && argv[3] && !parse_positive_int(argv[3], &tmp) && parse_hex_mode(argv[3]) == HEX_NONE && parse_json_mode(argv[3]) == JSON_NONE)) {
        printf("ERROR: Integer arguments must be between 1 and %d\n", MAX_PASSWORD_LENGTH);
        usage(cmd);
    }

    if (jsonmode == JSON_OUTPUT) {
        //Collect all passwords then emit JSON
        char (*passwords)[MAX_PASSWORD_LENGTH + 1] =
            malloc((size_t)count * sizeof(*passwords));
        if (!passwords) {
            fprintf(stderr, "ERROR: Out of memory\n");
            exit(1);
        }
        for (int i = 0; i < count; i++) {
            generate_random_password(passwords[i], length);
        }
        if (count == 1) {
            print_json_single(passwords[0]);
        } else {
            print_json_array(passwords, count);
        }
        free(passwords);
    } else {
        for (int i = 0; i < count; i++) {
            generate_random_password(out, length);
            print_with_hex(out, hexmode);
        }
    }

    exit(0);
}

//
// entry point
//

int main(int argc, char *argv[]) {
    char out[MAX_PASSWORD_LENGTH + 1] = {0};

    if (argc < 2) {
        printf("ERROR: Format string required!\n");
        usage(argv[0]);
    }

    if ((strcmp(argv[1], "--help") == 0) || (strcmp(argv[1], "-h") == 0)) {
        help(argv[0]);
    }

    if ((strcmp(argv[1], "--version") == 0) || (strcmp(argv[1], "-v") == 0)) {
        version();
    }


    if (strcmp(argv[1], "R") == 0) {
        handle_random_mode(argc, argv, out, argv[0]);
    }

    validate_format(argv[1], argv[0]);

    hex_mode_t  hexmode  = HEX_NONE;
    json_mode_t jsonmode = JSON_NONE;

    if (argc >= 4) {
        jsonmode = parse_json_mode(argv[3]);
        if (jsonmode == JSON_NONE) hexmode = parse_hex_mode(argv[3]);
    }

    //FORMAT MULTI-GENERATE MODE
    int count;

    if (argc >= 3 && parse_positive_int(argv[2], &count)) {
        if (jsonmode == JSON_OUTPUT) {
            char (*passwords)[MAX_PASSWORD_LENGTH + 1] =
                malloc((size_t)count * sizeof(*passwords));
            if (!passwords) {
                fprintf(stderr, "ERROR: Out of memory\n");
                exit(1);
            }
            for (int i = 0; i < count; i++) {
                generate_from_format(argv[1], passwords[i]);
            }
            if (count == 1) {
                print_json_single(passwords[0]);
            } else {
                print_json_array(passwords, count);
            }
            free(passwords);
        } else {
            for (int i = 0; i < count; i++) {
                generate_from_format(argv[1], out);
                print_with_hex(out, hexmode);
            }
        }
        return 0;
    }

    //SINGLE FORMAT GENERATION
    generate_from_format(argv[1], out);

    //SINGLE OUTPUT
    if (argc >= 3) {
        jsonmode = parse_json_mode(argv[2]);
        if (jsonmode == JSON_NONE) hexmode = parse_hex_mode(argv[2]);
    }

    if (jsonmode == JSON_OUTPUT) {
        print_json_single(out);
    } else {
        print_with_hex(out, hexmode);
    }

    return 0;
}
