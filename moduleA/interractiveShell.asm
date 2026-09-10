.386
.model flat, stdcall
.stack 4096

INCLUDE Irvine32.inc

.DATA
    ; Display manu
    promptIntro BYTE "Welcome to DES Encryption!", 0
    promptMsg BYTE "Enter message to encryption: ", 0
    promptKey BYTE "Enter key: ", 0
    resultMsg BYTE "Encrypted message: ", 0
    errorMsg BYTE "[-] Error: Invalid command", 0

    ; 7 menu
    cmdKeyGen BYTE "KEYGEN", 0
    cmdEn BYTE "ENCRYPT", 0
    cmdDe BYTE "DECRYPT", 0
    cmdDump BYTE "DUMP", 0
    cdmStat BYTE "STATS", 0
    cmdClear BYTE "CLEAR", 0
    cmdExit BYTE "EXIT", 0

    ; input buffer
    inputBuffer BYTE 64 DUP(0)


.CODE
main PROC

ShellLoop:
    ; 1. Show Prompt
    MOV EDX, OFFSET promptIntro
    call WriteString

    ; 2. Receive Message
    MOV EDX, OFFSET promptMsg
    MOV ECX, SIZEOF promptMsg - 1
    CALL ReadString

    cmp EDX, 0 ; ถ้าผู้ใช้ไม่ได้กรอกอะไรมา ให้เริ่มลูปใหม่
    je ShellLoop

    ; 3. if(Exit)
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdExit
    jz ExitShell

    ; 4. check keygen cmd
    INVOKE Str_compare, ADDR inputBuffer, ADDR cmdKeyGen
    jz DoKeyGen

    ; if !cmd in this system
    MOV EDX, OFFSET errorMsg
    call WriteString
    jmp ShellLoop

DoKeyGen:
    ; tum yang gnai