;; BF language interpreter written in fasm for windows x64
;; rgimad 2020
format PE64
entry start
include 'win64a.inc'

SEEK_SET equ 0
SEEK_CUR equ 1
SEEK_END equ 2
EOF      equ -1

section '.data' data readable writeable
        file_name       dq ?       ; char *file_name
        file_mode       db 'rb+', 0; file opening mode
        file_ptr        dq ?       ; FILE* file_ptr;
        file_size       dq ?       ; size of program
        code_buf        dq ?       ; pointer to the buf where bf program is stored
        open_braces_cnt dq 0       ; number of open braces
        bstack          dq ?       ; stack for storing [ position
        bstack_top      dq ?       ; pointer to top of the [ positions stack
        argc            dq ?       ; int argc
        argv            dq ?       ; char **argv
        envp            dq ?       ; envp
        sinfo           STARTUPINFO; startup info structure
        tmp             dq ?       ; temporary variable
        ; string constants:
        sz_no_inp_file  db '[-] Error: bf program file not specified.',13,10,0
        sz_file_not_found db '[-] File %s was not found.',13,10,0
        sz_unbalanced   db '(%d): error: unbalanced braces.',13,10,0

section '.bss' readable writeable  ; statically-allocated variables that are not explicitly initialized to any value
        mem_tape  rb 30000         ; bf memory tape - 30000 bytes

section '.text' code readable executable
start:
        sub     rsp, 40 ; 8(5th arg, align) + 32(shadow space)
        lea     rcx, [argc]
        lea     rdx, [argv]
        lea     r8, [envp]
        mov     r9, 0
        mov     qword [rsp + 8*4], sinfo
        call    [__getmainargs]

        mov     rbx, qword [argc]
        cmp     rbx, 2
        jae      @f
            mov     rcx, sz_no_inp_file
            call    [printf]
            jmp     Exit
        @@:
            mov     rax, [argv]
            mov     rax, [rax + 8]
            mov     [file_name], rax ; file_name = argv[1];
            mov     rcx, [file_name]
            mov     rdx, file_mode
            call    [fopen]
            mov     [file_ptr], rax  ; file_ptr = fopen(file_name, file_mode);
            test    rax, rax
            jnz     @f
                mov     rcx, sz_file_not_found
                mov     rdx, [file_name]
                call    [printf]
                jmp Exit
            @@:
        mov     rcx, [file_ptr]
        xor     rdx, rdx
        mov     r8, SEEK_END
        call    [fseek]
        mov     rcx, [file_ptr]
        call    [ftell]
        mov     [file_size], rax
        mov     rcx, [file_ptr]
        call    [rewind]

        mov     rcx, [file_size]
        inc     rcx
        call    [malloc]
        mov     [code_buf], rax

        ;read [file_size] chars (i.e 1 is size of each element)
        mov     rcx, [code_buf]
        mov     rdx, 1
        mov     r8, [file_size]
        mov     r9, [file_ptr]
        call    [fread]         ;!! returns number of bytes read. It will be equal to file_size, because binary file mode
        mov     rcx, [code_buf]
        mov     byte [rcx + rax], 0

        mov     rax, [code_buf]
        mov     rcx, [file_size]
        dec     rcx
        xor     rdx, rdx
    @@: cmp     byte [rax + rcx], '['
        pushf
        pop     rbx
        and     rbx, 0x40
        shr     rbx, 6
        add     rdx, rbx
        test    rcx, rcx
        jz      @f
        dec     rcx
        jmp     @b
    @@:
        mov     [open_braces_cnt], rdx

        mov     rax, [open_braces_cnt]
        add     rax, 5
        mov     rbx, 8
        mul     rbx
        mov     rcx, rax
        call    [malloc]
        mov     [bstack], rax
        mov     [bstack_top], -1

        xor     rsi, rsi ; current command index
        xor     rdi, rdi ; current cell index
        mov     rax, [code_buf]
        mov     rbx, mem_tape
        mov     rcx, [file_size]
        .while:
            cmp rsi, rcx
            jge .while_end
                cmp byte [rax + rsi], '+'
                jne @f
                    inc byte [rbx + rdi]
                    jmp .switch_end
                @@:
                cmp byte [rax + rsi], '-'
                jne @f
                    dec byte [rbx + rdi]
                    jmp .switch_end
                @@:
                cmp byte [rax + rsi], '>'
                jne @f
                    inc rdi
                    jmp .switch_end
                @@:
                cmp byte [rax + rsi], '<'
                jne @f
                    dec rdi
                    jmp .switch_end
                @@:
                cmp byte [rax + rsi], '.'     ;;
                jne @f
                    push rax rbx rcx rsi rdi
                    ; for shadow space!! its important, otherwise putchar will clobber preserved registers above
                    sub rsp, 40     ; +8 is align beacuse was pushhed non even number of registers
                    movzx rcx, byte [rbx + rdi]
                    call [putchar]
                    add rsp, 40
                    pop rdi rsi rcx rbx rax
                    jmp .switch_end
                @@:
                cmp byte [rax + rsi], ','     ;;
                jne .case_open
                    push rax rbx rcx rsi rdi
                    sub rsp, 40
                    call [getchar]
                    mov [tmp], rax
                    add rsp, 40
                    pop rdi rsi rcx rbx rax
                    cmp [tmp], EOF
                    jne @f
                        jmp .switch_end
                    @@:
                    mov r11, [tmp]
                    mov byte [rbx + rdi], r11l
                    jmp .switch_end
                .case_open:
                cmp byte [rax + rsi], '['     ;;
                jne .case_close
                        xor r8, r8  ; balance = 0
                        mov r9, rsi ; r9 is i
                        .for1:
                            cmp r9, [file_size]
                            jge .for1_end
                            cmp byte [rax + r9], '['
                            jne @f
                                inc r8
                            @@:
                            cmp byte [rax + r9], ']'
                            jne @f
                                dec r8
                                cmp r8, 0
                                jl .for1_end
                            @@:
                            cmp r8, 0
                            je .for1_end
                            inc r9
                            jmp .for1
                        .for1_end:
                        cmp r8, 0
                        jne @f
                            cmp byte [rbx + rdi], 0
                            je .else1
                                mov r10, [bstack]
                                inc [bstack_top]
                                mov r11, [bstack_top]
                                mov [r10 + r11*8], rsi
                                jmp .endif1
                            .else1:
                                mov rsi, r9
                            .endif1:
                            jmp .switch_end
                        @@:
                            mov rcx, sz_unbalanced
                            mov rdx, rsi
                            call [printf]
                            mov rcx, 1
                            call [exit]
                    jmp .switch_end;;!
                .case_close:
                cmp byte [rax + rsi], ']'     ;;
                jne .case_end
                    mov r10, [bstack]
                    mov r11, [bstack_top]
                    cmp byte [rbx + rdi], 0
                    je .else2
                        mov rsi, [r10 + r11*8]
                        jmp .endif2
                    .else2:
                        cmp r11, -1
                        jne @f
                            mov rcx, sz_unbalanced
                            mov rdx, rsi
                            call [printf]
                            mov rcx, 1
                            call [exit]
                        @@:
                            dec [bstack_top]
                    .endif2:
                .case_end:
                ;;;;;
            .switch_end:
            inc rsi
            jmp .while
        .while_end:

  Exit: call    [_getch]
        xor     rcx, rcx
        call    [ExitProcess]

section '.idata' import data readable

library msvcrt,'msvcrt.dll',\
        kernel,'kernel32.dll'
 
import  kernel,\
        ExitProcess, 'ExitProcess'

import  msvcrt,\
        scanf,'scanf',\
        printf,'printf',\
        fopen,'fopen',\
        fclose,'fclose',\
        fseek,'fseek',\
        ftell,'ftell',\
        rewind,'rewind',\
        fread,'fread',\
        malloc,'malloc',\
        free,'free',\
        putchar,'putchar',\
        getchar,'getchar',\
        _getch,'_getch',\
        system,'system',\
        __getmainargs,'__getmainargs',\
        exit,'exit'