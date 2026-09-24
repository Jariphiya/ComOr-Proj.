.386
.model flat, stdcall
.stack 4096
EXTERN main@0:PROC

INCLUDE Irvine32.inc

PUBLIC RunShell, inputBuffer, argFile, keyBytes, fileBuffer,
       outBuffer, fileSize, outSize

; =========================================================
; Constants
; =========================================================
MAX_INPUT EQU 256
MAX_FILE EQU 65536
CMD_COUNT EQU 7

; FSM states
S_GAP  EQU 0 ; between tokens (whitespace)
S_WORD EQU 1 ; inside unquote token
S_QARG EQU 2 ; inside "quote token"

.DATA
    ; Display manu
    promptIntro BYTE "=== Welcome to DES Encryption! ===", 0
    promptMenu BYTE "--- Available Commands ---", 0Dh, 0Ah
                BYTE "Keygen", 0Dh, 0Ah
               BYTE  "Encrypt Message/file", 0Dh, 0Ah
               BYTE  "Decrypt Message/file", 0Dh, 0Ah
               BYTE  "Dump", 0Dh, 0Ah
               BYTE  "Stat", 0Dh, 0Ah
               BYTE  "Clear", 0Dh, 0Ah
               BYTE  "Exit", 0Dh, 0Ah
               BYTE "(key = 16 hex digits, e.g. 0x133457799BBCDFF1)", 0
    promptShell BYTE "DES-Shell> ", 0
    promptMsg BYTE "Enter message/file to encryption: ", 0
    promptKey BYTE "Enter key: ", 0
    resultMsg BYTE "Encrypted message: ", 0

    ; Error Message
    errorMsgCmd BYTE "[-] Error: Invalid command", 0 ; dont find input command


    ; If user have input file

    ; Mock Message for testing
    msgEn BYTE "[+] Action: Encryption selected", 0
    msgDe BYTE "[+] Action: Decryption selected", 0
    msgDump BYTE "[+] Action: Memory Dump selected", 0
    msgStat BYTE "[+] Action: Displaying Statistics", 0

    ; 7 menu commands
    cmdKeyGen BYTE "KEYGEN", 0
    cmdEn BYTE "ENCRYPT", 0
    cmdDe BYTE "DECRYPT", 0
    cmdDump BYTE "DUMP", 0
    cmdStat BYTE "STATS", 0
    cmdClear BYTE "CLEAR", 0
    cmdExit BYTE "EXIT", 0

    ; input buffer
    inputBuffer BYTE 64 DUP(0)


.CODE

; =========================================================
; Procedure: Runshell (Main loop module A)
; =========================================================

RunShell PROC
    ; show banner
    mov edx, offset promptIntro
    call WriteString
    call Crlf

ShellLoop:
    ; =========================================================
    ; Show Shell & Menu Prompt
    ; =========================================================
    mov edx, OFFSET promptMenu ; show menu
    call WriteString
    call Crlf

    MOV EDX, OFFSET promptShell ; show prompt รับคำสั่ง
    call WriteString

    ; =========================================================
    ; Receive Message
    ; =========================================================
    MOV EDX, OFFSET inputBuffer
    MOV ECX, SIZEOF inputBuffer - 1
    CALL ReadString

    cmp EAX, 0 ; ถ้าผู้ใช้ไม่ได้กรอกอะไรมา ให้เริ่มลูปใหม่
    je ShellLoop

    ; turn into uppercase
    mov edx, offset inputBuffer
    call ToUpperCase

    ; =========================================================
    ; check commands (fsm parser)
    ; =========================================================
    
    ; 1. KeyGen
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdKeyGen
    jz DoKeyGen

    ; 2. Encrypt
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdEn
    jz DoEncrypt

    ; 3. Decrypt
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdDe
    jz DoDecrypt

    ; 4. Memory Dump
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdDump
    jz DoDump

    ; 5. Stats
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdStat
    jz DoStats

    ; 6. Clear
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdClear
    jz DoClear

    ; 7. Exit
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdExit
    jz ExitShell

    ; if cmd not in system
    MOV EDX, OFFSET errorMsgCmd
    call WriteString
    call Crlf
    jmp ShellLoop

; =========================================================
; Command Handlers
; =========================================================
DoKeyGen:
    mov edx, offset promptKey
    call WriteString
    call Crlf
    ; TODO: call ; call module B
    jmp ShellLoop

DoEncrypt:
    mov edx, offset msgEn
    call WriteString
    call Crlf
    ; TODO: call Encryption Procedure
    jmp ShellLoop

DoDecrypt:
    mov edx, offset msgDe
    call WriteString
    call Crlf
    ; TODO: call decryption procedure
    jmp ShellLoop

DoDump:
    mov edx, offset msgDump
    call WriteString
    ; TODO: call memory dump procedure
    call Crlf
    jmp ShellLoop

DoStats:
    mov edx, offset msgStat
    call WriteString
    ; call stat display procedure
    call Crlf
    jmp ShellLoop

DoClear:
    call Clrscr
    jmp ShellLoop

ExitShell:
    ret ; return value to main.asm
RunShell ENDP


; =========================================================
; Procedure: ToUpperCase
; =========================================================
ToUpperCase PROC
    push EDX
    push ESI

    mov esi, edx
ConvertLoop:
    mov al, [ESI]
    cmp al, 0
    je ConvertDone

    cmp al, 'a'
    jb NextChar
    cmp al, 'z'
    ja NextChar

    and al, 11011111b
    mov [esi], al

Nextchar:
    inc esi
    jmp ConvertLoop

ConvertDone:
    pop esi
    pop edx
    ret
ToUpperCase ENDP

END