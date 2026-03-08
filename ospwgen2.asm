; =============================================================================
; ospwgen_simple.asm  —  old school password generator
;                         x86-64 Linux, NASM, no libc
;
; Port of the refactored old_procedural/ospwgen.c
;
; Build:
;   nasm -f elf64 ospwgen_simple.asm -o ospwgen_simple.o
;   ld   -o ospwgen ospwgen_simple.o
;
; System V AMD64 ABI:
;   args:   rdi rsi rdx rcx r8 r9
;   return: rax
;   saved:  rbx rbp r12 r13 r14 r15
;   clobbered by syscall: rcx r11
; =============================================================================

bits 64

; ---------------------------------------------------------------------------
; Syscall numbers
; ---------------------------------------------------------------------------
SYS_read      equ 0
SYS_write     equ 1
SYS_open      equ 2
SYS_close     equ 3
SYS_exit      equ 60
SYS_getrandom equ 318

; ---------------------------------------------------------------------------
; Program constants
; ---------------------------------------------------------------------------
MAX_PW_LEN  equ 128
DEFAULT_LEN equ 14
STDOUT      equ 1
STDERR      equ 2

; arc4random / ChaCha20
KEYSZ       equ 32
IVSZ        equ 8
RSBUFSZ     equ 1024        ; 16 * 64
REKEY_BASE  equ 1048576     ; 1 << 20

; =============================================================================
section .data
; =============================================================================

; --- character sets ---
a_upper  db "ABCDEFGHIJKLMNOPQRSTUVWXYZ",0
a_upperc db "BCDFGHJKLMNPQRSTVWXYZ",0
a_upperv db "AEIOU",0
a_lower  db "abcdefghijklmnopqrstuvwxyz",0
a_lowerc db "bcdfghjklmnpqrstvwxyz",0
a_lowerv db "aeiou",0
a_digit  db "0123456789",0
a_symbl  db "!@#$%^&*()-+;:,.",0
a_all    db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-+;:,.",0
a_fstr   db "ulcvCVdsr",0

; --- character set lengths (written by init_lengths) ---
l_upper  dd 0
l_upperc dd 0
l_upperv dd 0
l_lower  dd 0
l_lowerc dd 0
l_lowerv dd 0
l_digit  dd 0
l_symbl  dd 0
l_all    dd 0

; --- hex tables ---
hex_lo db "0123456789abcdef"
hex_hi db "0123456789ABCDEF"

; --- messages ---
logo1  db 10,",-. ,-. ;-. , , , ,-: ,-. ;-.",10,0
logo2  db "| | `-. | | |/|/  | | |-' | |",10,0
logo3  db "`-' `-' |-' ' '   `-| `-' ' '",10,0
logo4  db "        '         `-'        ",10,0

s_usage_pre  db "Usage: ",0
s_usage_post db " <format string> [h]",10,10,0
s_fmtchars   db "Format string characters:",10,
             db "  u = uppercase letter",10,
             db "  l = lowercase letter",10,
             db "  c = consonant",10,
             db "  v = vowel",10,
             db "  C = uppercase consonant",10,
             db "  V = uppercase vowel",10,
             db "  d = digit",10,
             db "  s = symbol",10,
             db "  r = random printable character",10,10,
             db "Optional second argument:",10,
             db "  h  = show output in hex also",10,
             db "  H  = show output in uppercase hex also",10,
             db "  h0 = show output in hex only",10,
             db "  H0 = show output in uppercase hex only",10,10,
             db "Random passwords:",10,0
s_rand_pfx   db "  ",0
s_rand_b     db " R          = generate a random 14-character password",10,0
s_rand_d     db " R <n>      = generate a random password of <n> characters",10,0
s_rand_f     db " R <n1> <n2> = generate <n2> random passwords of <n1> characters",10,0

e_nofmt      db "ERROR: Format string required as argument!",10,0
e_fmtlong    db "ERROR: Format string must be 128 characters or fewer!",10,0
e_badchar_a  db "ERROR: Invalid character '",0
e_badchar_b  db "' at position ",0
e_badchar_c  db "!",10,0
e_randarg    db "ERROR: Arguments for R must be an integer between 1 and 128!",10,0
e_unkopt_a   db "ERROR: Unknown option '",0
e_unkopt_b   db "'.",10,0
e_entropy    db "FATAL: cannot get entropy",10,0

s_R          db "R",0
s_h          db "h",0
s_H          db "H",0
s_h0         db "h0",0
s_H0         db "H0",0
s_nl         db 10,0

; fallback path for getrandom
dev_urandom  db "/dev/urandom",0

; ChaCha20 sigma
sigma        db "expand 32-byte k"

; =============================================================================
section .bss
; =============================================================================

pw_buf       resb MAX_PW_LEN + 2   ; output password buffer

; arc4random state
rs_have      resq 1
rs_count     resq 1
rs_chacha    resd 16               ; chacha_ctx input[0..15]
rs_buf       resb RSBUFSZ
seed_buf     resb KEYSZ + IVSZ
rekey_fuzz   resd 1
urandom_fd   resd 1
rs_inited    resb 1

itoa_buf     resb 24

; =============================================================================
section .text
; =============================================================================

global _start

; ---------------------------------------------------------------------------
; MACRO: write NUL-terminated string rdi to fd r8d (trashes rax,rcx,rdx,rsi)
; Used inline in simple paths; functions use xputs/xputs_err below.
; ---------------------------------------------------------------------------

; ---------------------------------------------------------------------------
; xputs  — write NUL-terminated string to STDOUT
;   in:  rdi = ptr
; ---------------------------------------------------------------------------
xputs:
    push rbx
    mov  rbx, rdi
    xor  ecx, ecx
.l: cmp  byte [rbx+rcx], 0
    je   .w
    inc  ecx
    jmp  .l
.w: test ecx, ecx
    jz   .d
    mov  rdi, STDOUT
    mov  rsi, rbx
    mov  rdx, rcx
    mov  eax, SYS_write
    syscall
.d: pop  rbx
    ret

; ---------------------------------------------------------------------------
; xputs_err  — write NUL-terminated string to STDERR
;   in:  rdi = ptr
; ---------------------------------------------------------------------------
xputs_err:
    push rbx
    mov  rbx, rdi
    xor  ecx, ecx
.l: cmp  byte [rbx+rcx], 0
    je   .w
    inc  ecx
    jmp  .l
.w: test ecx, ecx
    jz   .d
    mov  rdi, STDERR
    mov  rsi, rbx
    mov  rdx, rcx
    mov  eax, SYS_write
    syscall
.d: pop  rbx
    ret

; ---------------------------------------------------------------------------
; xputc_out  — write single byte to STDOUT    in: dil = byte
; xputc_err  — write single byte to STDERR    in: dil = byte
; ---------------------------------------------------------------------------
xputc_out:
    sub  rsp, 8
    mov  [rsp], dil
    mov  rdi, STDOUT
    mov  rsi, rsp
    mov  rdx, 1
    mov  eax, SYS_write
    syscall
    add  rsp, 8
    ret

xputc_err:
    sub  rsp, 8
    mov  [rsp], dil
    mov  rdi, STDERR
    mov  rsi, rsp
    mov  rdx, 1
    mov  eax, SYS_write
    syscall
    add  rsp, 8
    ret

; ---------------------------------------------------------------------------
; strlen_asm — length of NUL-terminated string
;   in: rdi  out: eax
; ---------------------------------------------------------------------------
strlen_asm:
    xor  eax, eax
.l: cmp  byte [rdi+rax], 0
    je   .d
    inc  eax
    jmp  .l
.d: ret

; ---------------------------------------------------------------------------
; strcmp_asm — compare two strings
;   in: rdi=s1, rsi=s2   out: eax=0 if equal
; ---------------------------------------------------------------------------
strcmp_asm:
    xor  eax, eax
.l: movzx ecx, byte [rdi+rax]
    movzx edx, byte [rsi+rax]
    cmp  ecx, edx
    jne  .diff
    test ecx, ecx
    jz   .eq
    inc  eax
    jmp  .l
.diff:
    sub  ecx, edx
    mov  eax, ecx
    ret
.eq:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; strchr_asm — find byte sil in string rdi
;   out: rax = ptr to match, or 0
; ---------------------------------------------------------------------------
strchr_asm:
    xor  eax, eax
.l: movzx ecx, byte [rdi+rax]
    test ecx, ecx
    jz   .nf
    cmp  cl, sil
    je   .f
    inc  eax
    jmp  .l
.f: lea  rax, [rdi+rax]
    ret
.nf:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; itoa_dec — u32 edi -> NUL-terminated decimal in itoa_buf
;   out: rax = pointer to string
;   Clobbers: rax, rdx, r8, r9, r10  (rbx/rcx/rsi/rdi preserved)
; ---------------------------------------------------------------------------
itoa_dec:
    lea  r8,  [rel itoa_buf]
    mov  r9d, 23
    mov  byte [r8+r9], 0        ; NUL terminator at slot 23
    dec  r9d                    ; r9d = current write slot (22 initially)

    test edi, edi
    jnz  .lp
    mov  byte [r8+r9], '0'
    jmp  .dn

.lp:
    test edi, edi
    jz   .dn
    mov  eax, edi
    xor  edx, edx
    mov  r10d, 10
    div  r10d                   ; eax = quot, edx = remainder
    mov  edi, eax
    add  dl, '0'
    mov  [r8+r9], dl
    dec  r9d
    jmp  .lp

.dn:
    lea  rax, [r8+r9+1]
    ret

; ---------------------------------------------------------------------------
; parse_length — parse decimal string to int in [1..128], 0 on error
;   in: rdi   out: eax
; ---------------------------------------------------------------------------
parse_length:
    push rbx
    mov  rbx, rdi
    xor  eax, eax
    xor  ecx, ecx
.l: movzx edx, byte [rbx+rcx]
    test dl, dl
    jz   .end
    cmp  dl, '0'
    jl   .fail
    cmp  dl, '9'
    jg   .fail
    sub  dl, '0'
    imul eax, 10
    add  eax, edx
    cmp  eax, MAX_PW_LEN
    jg   .fail
    inc  ecx
    jmp  .l
.end:
    test ecx, ecx
    jz   .fail
    test eax, eax
    jz   .fail
    pop  rbx
    ret
.fail:
    xor  eax, eax
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; init_lengths — compute and store character set lengths
; ---------------------------------------------------------------------------
init_lengths:
    lea  rdi, [rel a_upper]
    call strlen_asm
    mov  [rel l_upper], eax

    lea  rdi, [rel a_upperc]
    call strlen_asm
    mov  [rel l_upperc], eax

    lea  rdi, [rel a_upperv]
    call strlen_asm
    mov  [rel l_upperv], eax

    lea  rdi, [rel a_lower]
    call strlen_asm
    mov  [rel l_lower], eax

    lea  rdi, [rel a_lowerc]
    call strlen_asm
    mov  [rel l_lowerc], eax

    lea  rdi, [rel a_lowerv]
    call strlen_asm
    mov  [rel l_lowerv], eax

    lea  rdi, [rel a_digit]
    call strlen_asm
    mov  [rel l_digit], eax

    lea  rdi, [rel a_symbl]
    call strlen_asm
    mov  [rel l_symbl], eax

    lea  rdi, [rel a_all]
    call strlen_asm
    mov  [rel l_all], eax
    ret

; ---------------------------------------------------------------------------
; usage — print help then exit(1)    in: rdi = argv[0]
; ---------------------------------------------------------------------------
usage:
    push rbx
    mov  rbx, rdi

    lea  rdi, [rel logo1]
    call xputs
    lea  rdi, [rel logo2]
    call xputs
    lea  rdi, [rel logo3]
    call xputs
    lea  rdi, [rel logo4]
    call xputs

    lea  rdi, [rel s_usage_pre]
    call xputs
    mov  rdi, rbx
    call xputs
    lea  rdi, [rel s_usage_post]
    call xputs

    lea  rdi, [rel s_fmtchars]
    call xputs

    lea  rdi, [rel s_rand_pfx]
    call xputs
    mov  rdi, rbx
    call xputs
    lea  rdi, [rel s_rand_b]
    call xputs

    lea  rdi, [rel s_rand_pfx]
    call xputs
    mov  rdi, rbx
    call xputs
    lea  rdi, [rel s_rand_d]
    call xputs

    lea  rdi, [rel s_rand_pfx]
    call xputs
    mov  rdi, rbx
    call xputs
    lea  rdi, [rel s_rand_f]
    call xputs

    mov  edi, 1
    mov  eax, SYS_exit
    syscall
    pop  rbx  ; unreachable
    ret

; ---------------------------------------------------------------------------
; gen_random — fill buf[0..len-1] with random a_all chars, NUL-terminate
;   in: rdi=buf, esi=len
; ---------------------------------------------------------------------------
gen_random:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    xor  r13d, r13d
.l:
    cmp  r13d, r12d
    jge  .d
    mov  edi, [rel l_all]
    call arc4random_uniform
    lea  rcx, [rel a_all]
    movzx eax, byte [rcx+rax]
    mov  [rbx+r13], al
    inc  r13d
    jmp  .l
.d:
    mov  byte [rbx+r13], 0
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; gen_from_format — generate password from format string
;   in: rdi=buf, rsi=fmt, edx=len
; ---------------------------------------------------------------------------
gen_from_format:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    xor  r14d, r14d   ; i

.l:
    cmp  r14d, r13d
    jge  .d
    movzx eax, byte [r12+r14]

    ; dispatch on format character
    cmp  al, 'u'
    jne  .t1
    mov  edi, [rel l_upper]
    call arc4random_uniform
    lea  rcx, [rel a_upper]
    jmp  .st
.t1:
    cmp  al, 'l'
    jne  .t2
    mov  edi, [rel l_lower]
    call arc4random_uniform
    lea  rcx, [rel a_lower]
    jmp  .st
.t2:
    cmp  al, 'c'
    jne  .t3
    mov  edi, [rel l_lowerc]
    call arc4random_uniform
    lea  rcx, [rel a_lowerc]
    jmp  .st
.t3:
    cmp  al, 'v'
    jne  .t4
    mov  edi, [rel l_lowerv]
    call arc4random_uniform
    lea  rcx, [rel a_lowerv]
    jmp  .st
.t4:
    cmp  al, 'C'
    jne  .t5
    mov  edi, [rel l_upperc]
    call arc4random_uniform
    lea  rcx, [rel a_upperc]
    jmp  .st
.t5:
    cmp  al, 'V'
    jne  .t6
    mov  edi, [rel l_upperv]
    call arc4random_uniform
    lea  rcx, [rel a_upperv]
    jmp  .st
.t6:
    cmp  al, 'd'
    jne  .t7
    mov  edi, [rel l_digit]
    call arc4random_uniform
    lea  rcx, [rel a_digit]
    jmp  .st
.t7:
    cmp  al, 's'
    jne  .t8
    mov  edi, [rel l_symbl]
    call arc4random_uniform
    lea  rcx, [rel a_symbl]
    jmp  .st
.t8:
    cmp  al, 'r'
    jne  .nx
    mov  edi, [rel l_all]
    call arc4random_uniform
    lea  rcx, [rel a_all]
.st:
    movzx eax, byte [rcx+rax]
    mov  [rbx+r14], al
.nx:
    inc  r14d
    jmp  .l
.d:
    mov  byte [rbx+r14], 0
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; print_hex — print buf as hex + newline
;   in: rdi=buf, esi=len, edx=uppercase(0/1)
; ---------------------------------------------------------------------------
print_hex:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    test edx, edx
    lea  r13, [rel hex_lo]
    jz   .go
    lea  r13, [rel hex_hi]
.go:
    xor  ecx, ecx
.l:
    cmp  ecx, r12d
    jge  .nl
    movzx eax, byte [rbx+rcx]
    mov  edx, eax
    shr  edx, 4
    and  edx, 0xf
    movzx edi, byte [r13+rdx]
    call xputc_out
    movzx eax, byte [rbx+rcx]   ; reload (xputc_out may trash eax)
    and  eax, 0xf
    movzx edi, byte [r13+rax]
    call xputc_out
    inc  ecx
    jmp  .l
.nl:
    mov  dil, 10
    call xputc_out
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; handle_hex — print with hex modifier (recognised options only), then exit(0)
;   in: rdi=pw, esi=len, rdx=mode string
; ---------------------------------------------------------------------------
handle_hex:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx

    mov  rdi, r13
    lea  rsi, [rel s_h]
    call strcmp_asm
    test eax, eax
    jnz  .tH
    ; "h": pw + newline, then lowercase hex
    mov  rdi, rbx
    call xputs
    lea  rdi, [rel s_nl]
    call xputs
    mov  rdi, rbx
    mov  esi, r12d
    xor  edx, edx
    call print_hex
    jmp  .ok

.tH:
    mov  rdi, r13
    lea  rsi, [rel s_H]
    call strcmp_asm
    test eax, eax
    jnz  .th0
    ; "H": pw + newline, then uppercase hex
    mov  rdi, rbx
    call xputs
    lea  rdi, [rel s_nl]
    call xputs
    mov  rdi, rbx
    mov  esi, r12d
    mov  edx, 1
    call print_hex
    jmp  .ok

.th0:
    mov  rdi, r13
    lea  rsi, [rel s_h0]
    call strcmp_asm
    test eax, eax
    jnz  .tH0
    ; "h0": lowercase hex only
    mov  rdi, rbx
    mov  esi, r12d
    xor  edx, edx
    call print_hex
    jmp  .ok

.tH0:
    mov  rdi, r13
    lea  rsi, [rel s_H0]
    call strcmp_asm
    test eax, eax
    jnz  .unk
    ; "H0": uppercase hex only
    mov  rdi, rbx
    mov  esi, r12d
    mov  edx, 1
    call print_hex
    jmp  .ok

.unk:
    lea  rdi, [rel e_unkopt_a]
    call xputs_err
    mov  rdi, r13
    call xputs_err
    lea  rdi, [rel e_unkopt_b]
    call xputs_err
    mov  edi, 1
    mov  eax, SYS_exit
    syscall

.ok:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; handle_random — R mode, generates and prints, then exit(0)
;   in: rdi=argv[0], esi=argc, rdx=argv
; ---------------------------------------------------------------------------
handle_random:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi     ; argv[0]
    mov  r12d, esi    ; argc
    mov  r13, rdx     ; argv
    mov  r14d, DEFAULT_LEN
    mov  r15d, 1

    cmp  r12d, 3
    jl   .gen
    mov  rdi, [r13+16]
    call parse_length
    test eax, eax
    jz   .err
    mov  r14d, eax

    cmp  r12d, 4
    jl   .gen
    mov  rdi, [r13+24]
    call parse_length
    test eax, eax
    jz   .err
    mov  r15d, eax

.gen:
    xor  ecx, ecx
.loop:
    cmp  ecx, r15d
    jge  .exit
    push rcx
    lea  rdi, [rel pw_buf]
    mov  esi, r14d
    call gen_random
    lea  rdi, [rel pw_buf]
    call xputs
    lea  rdi, [rel s_nl]
    call xputs
    pop  rcx
    inc  ecx
    jmp  .loop

.exit:
    xor  edi, edi
    mov  eax, SYS_exit
    syscall

.err:
    lea  rdi, [rel e_randarg]
    call xputs_err
    mov  rdi, rbx
    call usage      ; exits

    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; =============================================================================
; _start
; =============================================================================
_start:
    mov  rbx, [rsp]       ; argc
    lea  r12, [rsp+8]     ; argv

    cmp  rbx, 2
    jge  .ok
    lea  rdi, [rel e_nofmt]
    call xputs_err
    mov  rdi, [r12]
    call usage

.ok:
    call init_lengths

    ; R mode?
    mov  rdi, [r12+8]
    lea  rsi, [rel s_R]
    call strcmp_asm
    test eax, eax
    jnz  .fmt

    mov  rdi, [r12]
    mov  esi, ebx
    mov  rdx, r12
    call handle_random    ; exits inside

.fmt:
    mov  r13, [r12+8]     ; fmt string = argv[1]
    mov  rdi, r13
    call strlen_asm
    mov  r14d, eax        ; fmtlen

    cmp  r14d, MAX_PW_LEN
    jle  .lenok
    lea  rdi, [rel e_fmtlong]
    call xputs_err
    mov  rdi, [r12]
    call usage

.lenok:
    ; validate format chars
    xor  r15d, r15d
.val:
    cmp  r15d, r14d
    jge  .val_done
    movzx esi, byte [r13+r15]
    lea  rdi, [rel a_fstr]
    call strchr_asm
    test rax, rax
    jnz  .val_next

    ; bad char error
    lea  rdi, [rel e_badchar_a]
    call xputs_err
    movzx edi, byte [r13+r15]
    call xputc_err
    lea  rdi, [rel e_badchar_b]
    call xputs_err
    mov  edi, r15d
    inc  edi
    call itoa_dec
    mov  rdi, rax
    call xputs_err
    lea  rdi, [rel e_badchar_c]
    call xputs_err
    mov  rdi, [r12]
    call usage

.val_next:
    inc  r15d
    jmp  .val

.val_done:
    ; generate password
    lea  rdi, [rel pw_buf]
    mov  rsi, r13
    mov  edx, r14d
    call gen_from_format

    ; hex modifier?
    cmp  rbx, 3
    jl   .plain

    lea  rdi, [rel pw_buf]
    mov  esi, r14d
    mov  rdx, [r12+16]
    call handle_hex
    xor  edi, edi
    mov  eax, SYS_exit
    syscall

.plain:
    lea  rdi, [rel pw_buf]
    call xputs
    lea  rdi, [rel s_nl]
    call xputs
    xor  edi, edi
    mov  eax, SYS_exit
    syscall

; =============================================================================
; ChaCha20-based arc4random
; Sources:
;   chacha.c  D.J. Bernstein, public domain (via OpenSSH)
;   arc4random.c  OpenBSD, ISC license
;     Copyright (c) 1996 David Mazieres
;     Copyright (c) 2008 Damien Miller
;     Copyright (c) 2013 Markus Friedl
;     Copyright (c) 2014 Theo de Raadt
; =============================================================================

; ---------------------------------------------------------------------------
; getentropy_impl  — fill buf with n entropy bytes
;   in: rdi=buf, rsi=n    out: eax=0 ok / -1 fail
; ---------------------------------------------------------------------------
getentropy_impl:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    xor  r13d, r13d

.grnd:
    cmp  r13, r12
    jge  .ok
    lea  rdi, [rbx+r13]
    mov  rsi, r12
    sub  rsi, r13
    xor  edx, edx
    mov  eax, SYS_getrandom
    syscall
    cmp  eax, -38
    je   .fallback
    test eax, eax
    js   .grnd
    add  r13, rax
    jmp  .grnd

.fallback:
    lea  rdi, [rel dev_urandom]
    xor  esi, esi
    xor  edx, edx
    mov  eax, SYS_open
    syscall
    test eax, eax
    js   .fail
    mov  [rel urandom_fd], eax

.urd:
    cmp  r13, r12
    jge  .close_ok
    mov  edi, [rel urandom_fd]
    lea  rsi, [rbx+r13]
    mov  rdx, r12
    sub  rdx, r13
    mov  eax, SYS_read
    syscall
    test eax, eax
    jle  .close_fail
    add  r13, rax
    jmp  .urd

.close_ok:
    mov  edi, [rel urandom_fd]
    mov  eax, SYS_close
    syscall
.ok:
    xor  eax, eax
    pop  r13; pop r12; pop rbx
    ret

.close_fail:
    mov  edi, [rel urandom_fd]
    mov  eax, SYS_close
    syscall
.fail:
    mov  eax, -1
    pop  r13; pop r12; pop rbx
    ret

; ---------------------------------------------------------------------------
; chacha_keysetup
;   in: rdi=ctx*, rsi=key(32 bytes), edx=kbits(256)
; ---------------------------------------------------------------------------
chacha_keysetup:
    push rbx
    mov  rbx, rdi
    ; input[4..7] = key[0..15]
    mov  eax, [rsi+ 0]; mov [rbx+16], eax
    mov  eax, [rsi+ 0]
    mov  [rbx+16], eax
    mov  eax, [rsi+ 4]
    mov  [rbx+20], eax
    mov  eax, [rsi+ 8]
    mov  [rbx+24], eax
    mov  eax, [rsi+12]
    mov  [rbx+28], eax
    ; input[8..11] = key[16..31]
    mov  eax, [rsi+16]
    mov  [rbx+32], eax
    mov  eax, [rsi+20]
    mov  [rbx+36], eax
    mov  eax, [rsi+24]
    mov  [rbx+40], eax
    mov  eax, [rsi+28]
    mov  [rbx+44], eax
    ; input[0..3] = sigma
    lea  rcx, [rel sigma]
    mov  eax, [rcx+ 0]
    mov  [rbx+ 0], eax
    mov  eax, [rcx+ 4]
    mov  [rbx+ 4], eax
    mov  eax, [rcx+ 8]
    mov  [rbx+ 8], eax
    mov  eax, [rcx+12]
    mov  [rbx+12], eax
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; chacha_ivsetup
;   in: rdi=ctx*, rsi=iv(8 bytes), rdx=counter ptr (or 0=NULL)
; ---------------------------------------------------------------------------
chacha_ivsetup:
    test rdx, rdx
    jz   .zc
    mov  eax, [rdx+0]; mov [rdi+48], eax
    mov  eax, [rdx+0]
    mov  [rdi+48], eax
    mov  eax, [rdx+4]
    mov  [rdi+52], eax
    jmp  .iv
.zc:
    mov  dword [rdi+48], 0
    mov  dword [rdi+52], 0
.iv:
    mov  eax, [rsi+0]
    mov  [rdi+56], eax
    mov  eax, [rsi+4]
    mov  [rdi+60], eax
    ret

; ---------------------------------------------------------------------------
; chacha_encrypt_bytes
;   in: rdi=ctx*, rsi=m, rdx=c, ecx=bytes
;
; Stack layout (rbp-relative, frame=240):
;   rbp- 8  ctx*      (8)
;   rbp-16  m*        (8)
;   rbp-24  c*        (8)
;   rbp-32  ctarget*  (8)
;   rbp-36  bytes     (4)
;   rbp-40  pad       (4)
;   rbp-104 j[0..15]  (64)   j[i] at rbp-104+i*4
;   rbp-168 x[0..15]  (64)   x[i] at rbp-168+i*4  (NO overlap with j[])
;   rbp-232 tmp[64]
; ---------------------------------------------------------------------------
chacha_encrypt_bytes:
    push rbp
    mov  rbp, rsp
    sub  rsp, 240

    test ecx, ecx
    jz   .ret

    mov  [rbp- 8], rdi
    mov  [rbp-16], rsi
    mov  [rbp-24], rdx
    mov  dword [rbp-36], ecx
    mov  qword [rbp-32], 0

    ; load j[0..15] from ctx (rdi still valid)
%assign _i 0
%rep 16
    mov  eax, [rdi+_i*4]
    mov  [rbp-104+_i*4], eax
%assign _i _i+1
%endrep

.outer:
    mov  ecx, dword [rbp-36]
    test ecx, ecx
    jz   .ret

    cmp  ecx, 64
    jge  .full

    ; partial: save ctarget, redirect m/c to tmp
    mov  rax, [rbp-16]
    lea  rdi, [rbp-232]
    xor  edx, edx
.cpin:
    cmp  edx, ecx
    jge  .cpin_d
    movzx r8d, byte [rax+rdx]
    mov  [rdi+rdx], r8b
    inc  edx
    jmp  .cpin
.cpin_d:
    mov  rax, [rbp-24]
    mov  [rbp-32], rax
    lea  rdi, [rbp-232]
    mov  [rbp-16], rdi
    mov  [rbp-24], rdi

.full:
    ; x[i] = j[i]
%assign _i 0
%rep 16
    mov  eax, [rbp-104+_i*4]
    mov  [rbp-168+_i*4], eax
%assign _i _i+1
%endrep

    ; 10 double-rounds
    ; QR(a,b,c,d): all indices into x[] at [rbp-168+i*4]
    ; Uses eax/ecx/edx only — no rbx push needed inside macro
%macro QR 4
    mov  eax, [rbp-168+%1*4]
    add  eax, [rbp-168+%2*4]
    mov  [rbp-168+%1*4], eax
    mov  edx, [rbp-168+%4*4]
    xor  edx, eax
    rol  edx, 16
    mov  [rbp-168+%4*4], edx
    mov  ecx, [rbp-168+%3*4]
    add  ecx, edx
    mov  [rbp-168+%3*4], ecx
    mov  edx, [rbp-168+%2*4]
    xor  edx, ecx
    rol  edx, 12
    mov  [rbp-168+%2*4], edx
    add  eax, edx
    mov  [rbp-168+%1*4], eax
    mov  edx, [rbp-168+%4*4]
    xor  edx, eax
    rol  edx, 8
    mov  [rbp-168+%4*4], edx
    add  ecx, edx
    mov  [rbp-168+%3*4], ecx
    mov  edx, [rbp-168+%2*4]
    xor  edx, ecx
    rol  edx, 7
    mov  [rbp-168+%2*4], edx
%endmacro

%rep 10
    QR  0, 4,  8, 12
    QR  1, 5,  9, 13
    QR  2, 6, 10, 14
    QR  3, 7, 11, 15
    QR  0, 5, 10, 15
    QR  1, 6, 11, 12
    QR  2, 7,  8, 13
    QR  3, 4,  9, 14
%endrep

    ; x[i] += j[i]
%assign _i 0
%rep 16
    mov  eax, [rbp-168+_i*4]
    add  eax, [rbp-104+_i*4]
    mov  [rbp-168+_i*4], eax
%assign _i _i+1
%endrep

    ; output[i] = x[i] XOR m[i]  (KEYSTREAM_ONLY: m=c=rs_buf, zeros XOR x = x)
    mov  rsi, [rbp-16]
    mov  rdx, [rbp-24]
%assign _i 0
%rep 16
    mov  eax, [rbp-168+_i*4]
    xor  eax, [rsi+_i*4]
    mov  [rdx+_i*4], eax
%assign _i _i+1
%endrep

    ; counter j[12]++, carry to j[13]
    mov  eax, [rbp-104+48]
    inc  eax
    mov  [rbp-104+48], eax
    jnz  .nc
    mov  eax, [rbp-104+52]
    inc  eax
    mov  [rbp-104+52], eax
.nc:

    mov  ecx, dword [rbp-36]
    cmp  ecx, 64
    jg   .more

    ; final block
    cmp  ecx, 64
    je   .sc
    ; partial: copy tmp[0..ecx) to ctarget
    mov  rdi, [rbp-32]
    lea  rsi, [rbp-232]
    xor  edx, edx
.cpout:
    cmp  edx, ecx
    jge  .sc
    movzx r8d, byte [rsi+rdx]
    mov  [rdi+rdx], r8b
    inc  edx
    jmp  .cpout

.sc:
    ; write back updated counter to ctx
    mov  rdi, [rbp-8]
    mov  eax, [rbp-104+48]
    mov  [rdi+48], eax
    mov  eax, [rbp-104+52]
    mov  [rdi+52], eax
    jmp  .ret

.more:
    sub  dword [rbp-36], 64
    add  qword [rbp-16], 64
    add  qword [rbp-24], 64
    jmp  .outer

.ret:
    mov  rsp, rbp
    pop  rbp
    ret

; ---------------------------------------------------------------------------
; _rs_rekey — refill keystream, reinit ctx for forward secrecy
;   in: rdi=extra seed (or 0), rsi=datlen
; ---------------------------------------------------------------------------
_rs_rekey:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi

    ; generate RSBUFSZ bytes of keystream into rs_buf
    lea  rdi, [rel rs_chacha]
    lea  rsi, [rel rs_buf]
    lea  rdx, [rel rs_buf]
    mov  ecx, RSBUFSZ
    call chacha_encrypt_bytes

    ; XOR in optional seed data (up to KEYSZ+IVSZ bytes)
    test rbx, rbx
    jz   .nomix
    mov  r13, r12
    cmp  r13, KEYSZ+IVSZ
    jle  .mix
    mov  r13, KEYSZ+IVSZ
.mix:
    xor  ecx, ecx
.mxl:
    cmp  rcx, r13
    jge  .nomix
    movzx eax, byte [rbx+rcx]
    lea  rdi, [rel rs_buf]
    xor  [rdi+rcx], al
    inc  rcx
    jmp  .mxl
.nomix:

    ; reinit with rs_buf[0..39] (forward secrecy)
    lea  rdi, [rel rs_chacha]
    lea  rsi, [rel rs_buf]
    mov  edx, 256
    call chacha_keysetup

    lea  rdi, [rel rs_chacha]
    lea  rsi, [rel rs_buf+KEYSZ]
    xor  edx, edx
    call chacha_ivsetup

    ; zero rs_buf[0..39]
    lea  rdi, [rel rs_buf]
    xor  eax, eax
    mov  ecx, KEYSZ+IVSZ
    rep  stosb

    mov  qword [rel rs_have], RSBUFSZ-KEYSZ-IVSZ

    pop  r13; pop r12; pop rbx
    ret

; ---------------------------------------------------------------------------
; _rs_stir — seed/reseed the generator
; ---------------------------------------------------------------------------
_rs_stir:
    lea  rdi, [rel seed_buf]
    mov  rsi, KEYSZ+IVSZ
    call getentropy_impl
    test eax, eax
    js   .ef

    cmp  byte [rel rs_inited], 0
    jne  .already

    lea  rdi, [rel rs_chacha]
    lea  rsi, [rel seed_buf]
    mov  edx, 256
    call chacha_keysetup

    lea  rdi, [rel rs_chacha]
    lea  rsi, [rel seed_buf+KEYSZ]
    xor  edx, edx
    call chacha_ivsetup

    mov  byte [rel rs_inited], 1
    jmp  .after

.already:
    lea  rdi, [rel seed_buf]
    mov  rsi, KEYSZ+IVSZ
    call _rs_rekey

.after:
    ; zero seed_buf
    lea  rdi, [rel seed_buf]
    xor  eax, eax
    mov  ecx, KEYSZ+IVSZ
    rep  stosb

    ; reset rs_buf
    mov  qword [rel rs_have], 0
    lea  rdi, [rel rs_buf]
    xor  eax, eax
    mov  ecx, RSBUFSZ
    rep  stosb

    ; randomise rekey interval
    lea  rdi, [rel rs_chacha]
    lea  rsi, [rel rekey_fuzz]
    lea  rdx, [rel rekey_fuzz]
    mov  ecx, 4
    call chacha_encrypt_bytes

    mov  eax, [rel rekey_fuzz]
    xor  edx, edx
    mov  ecx, REKEY_BASE
    div  ecx
    add  edx, REKEY_BASE
    mov  [rel rs_count], rdx
    ret

.ef:
    lea  rdi, [rel e_entropy]
    call xputs_err
    mov  edi, 1
    mov  eax, SYS_exit
    syscall

; ---------------------------------------------------------------------------
; _rs_stir_if_needed   in: rdi=bytes needed
; ---------------------------------------------------------------------------
_rs_stir_if_needed:
    push rbx
    mov  rbx, rdi
    cmp  byte [rel rs_inited], 0
    je   .stir
    cmp  [rel rs_count], rbx
    jg   .sub
.stir:
    call _rs_stir
    cmp  [rel rs_count], rbx
    jg   .sub
    mov  qword [rel rs_count], 0
    pop  rbx
    ret
.sub:
    sub  [rel rs_count], rbx
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; arc4random_uniform — uniform u32 in [0, upper_bound)
;   in:  edi = upper_bound
;   out: eax = result
;
; Register usage:
;   r12d = upper_bound  (callee-saved, survives arc4 calls)
;   r13d = min threshold (callee-saved, survives syscall in arc4 internals)
;   rbx  = scratch (saved/restored)
; ---------------------------------------------------------------------------
arc4random_uniform:
    push rbx
    push r12
    push r13
    mov  r12d, edi       ; upper_bound

    test r12d, r12d
    jz   .zero
    cmp  r12d, 1
    je   .zero

    ; rejection threshold = (uint32)(-upper) % upper
    xor  eax, eax
    sub  eax, r12d       ; eax = (u32)(-upper)
    xor  edx, edx
    div  r12d            ; edx = min
    mov  r13d, edx       ; r13d survives any syscall

.retry:
    mov  rdi, 4
    call _rs_stir_if_needed

    ; consume 4 bytes from keystream
    mov  rax, [rel rs_have]
    cmp  rax, 4
    jge  .have4
    xor  edi, edi
    xor  esi, esi
    call _rs_rekey
    mov  rax, [rel rs_have]

.have4:
    lea  rcx, [rel rs_buf+RSBUFSZ]
    sub  rcx, rax
    mov  ebx, [rcx]          ; random u32
    mov  dword [rcx], 0      ; zero keystream bytes (forward secrecy)
    sub  qword [rel rs_have], 4

    ; reject if in bias zone
    cmp  ebx, r13d
    jb   .retry

    ; result = random % upper_bound
    mov  eax, ebx
    xor  edx, edx
    div  r12d                ; edx = eax % r12d
    mov  eax, edx

    pop  r13
    pop  r12
    pop  rbx
    ret

.zero:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    ret
