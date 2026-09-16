.386
.model flat, stdcall
option casemap:none

INCLUDE Irvine32.inc
INCLUDELIB Irvine32.lib

;-----------------------------------------------------------------------------
;                                 DATA SEGMENT
;-----------------------------------------------------------------------------

.DATA
;Permutation Choice 1 mapping table
PC1Table BYTE 57,49,41,33,25,17,9,1,
            BYTE 58,50,42,34,26,18,10,2,
            BYTE 59,51,43,35,27,19,11,3,
            BYTE 60,52,44,36,63,55,47,39,
            BYTE 31,23,15,7,62,54,46,38,
            BYTE 30,22,14,6,61,53,45,37,
            BYTE 29,21,13,5,28,20,12,4

PC2Table BYTE 14,17,11,24,1,5,
            BYTE 3,28,15,6,21,10,
            BYTE 23,19,12,4,26,8,
            BYTE 16,7,27,20,13,2,
            BYTE 41,52,31,37,47,55,
            BYTE 30,40,51,45,33,48,
            BYTE 44,49,39,56,34,53,
            BYTE 46,42,50,36,29,32

ShiftSchedule BYTE 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1

;-----------------------------------------------------------------------------
;                               CODE SEGMENT
;-----------------------------------------------------------------------------

.CODE

;------------------------------------------------------------------------------
;(1)Get Bits
;GetBit(bufferPtr, bitNumber) -> EAX = 0 / 1
;Read single bit from byte buffer: bitNumber is 1-based, with bit 1 being the MSB of the first byte in the buffer(byte 0). 

GetBit PROC bufferPtr:PTR BYTE, bitNumber:Dword
    LOCAL byteIndex:Dword
    LOCAL bitInByte:Dword
    LOCAL shiftAmt:Dword

    mov eax, bitNumber
    dec eax                 ; Convert to 0-based index  
    mov ebx, eax
    shr eax, 3                 ; eax = byteIndex = bitIndex / 8
    mov byteIndex, eax
    and ebx, 7                ; ebx = bitInByte = bitIndex % 8
    mov bitInByte, ebx
    mov eax, 7
    sub eax, ebx               ;MSB-fist: shift = 7 - bitInByte
    mov shiftAmt, eax

    mov eax, [bufferPtr]      ; Load the byte from the buffer
    movzx eax, byte ptr [eax + byteIndex] ; Load the byte at bufferPtr + byteIndex
    shr eax, shiftAmt         ; Shift right to get the desired bit in LSB position
    and eax, 1                ; Mask out all but the LSB
    ret
GetBit ENDP
;------------------------------------------------------------------------------

;---------------------------------------------------------------
;SetBit(bufferPtr, bitNumber, bitValue)
;write single bit into byte buffer using 1-based MSB-first numbering (same as GetBit). bitValue is 0 or 1.

SetBit PROC bufferPtr: PTR BYTE, bitNumber:DWORD, bitValue:DWord
    LOCAL byteIndex:Dword
    LOCAl bitInByte:Dword
    LOCAL shiftAmt:Dword
    LOCAL maskBit:Dword

    mov eax, bitNumber
    dec eax
    mov ebx, eax
    shr eax, 3
    mov byteIndex, eax
    and ebx, 7
    mov bitInByte, ebx
    mov eax, 7
    sub eax, ebx
    mov shiftAmt, eax

    mov edi, bufferPtr
    add edi, byteIndex

    mov ecx, shiftAmt
    mov eax, 1
    shl eax, cl
    mov maskBit,eax             ;maskBit = 1 << shiftAmt

    movzx eax, BYTE PTR [edi]  
    mo ebx, maskBit
    not ebx
    and eax, ebx                ; Clear the target bit

    cmp bitValue, 0
    je SetBit_Store
    or eax, maskBit             ; Set it back to 1 if bitValue is 1

SetBit_Store:
    mov BYTE PTR [edi], al      ; Store the modified byte back to the buffer
    ret
SetBit ENDP
;------------------------------------------------------------------------------