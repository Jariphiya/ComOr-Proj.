.386
.model flat, stdcall
.STACK 4096

include Irvine32.inc

; ประกาศอ้างอิงฟังก์ชัน + ตัวแปรจาก module A (interractiveShell.asm)
EXTERN RunShell@0 : PROC
EXTERN inputBuffer : BYTE
PUBLIC main

.CODE
main PROC
    ; call shell loop (module A)
    call RunShell@0

    exit
main ENDP

END main