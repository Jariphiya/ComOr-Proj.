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
-------------------------------------------------------------------------------
PUBLIC GetBit
Public SetBit
Public PC1Table, PC2Table, ShiftSchedule
-------------------------------------------------------------------------------


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

    mov esi, bufferPtr
    add esi, byteIndex
    movzx eax, BYTE PTR [esi]
    mov ecx, shiftAmt
    shr eax, cl
    and eax, 1
    ret
GetBit ENDP
;------------------------------------------------------------------------------

;------------------------------------------------------------------------------
;SetBit(bufferPtr, bitNumber, bitValue)
;write single bit into byte buffer using 1-based MSB-first numbering (same as GetBit). bitValue is 0 or 1.

SetBit PROC bufferPtr: PTR BYTE, bitNumber:DWORD, bitValue:DWord
    LOCAL byteIndex:Dword
    LOCAL bitInByte:Dword
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
    mov ebx, maskBit
    not ebx
    and eax, ebx                ; Clear the target bit

    cmp bitValue, 0
    je SetBit_Store
    or eax, maskBit             ; Set it back to 1 if bitValue is 1

SetBit_Store:
    mov BYTE PTR [edi], al      ; Store the modified byte back to the buffer
    ret
SetBit ENDP
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
;PermutateBits(srcPtr, destPtr, tablePtr, tableLen)
;For every entry i in the table, destBit(i+1) = srcBit(table[i])
;can be reuse for PC1, PC2, IP, Ip-1
;destPtr must point to buffer with at least (tableLen/8) bytes

PermutateBits Proc scrPtr:PTR BYTE, destPtr: PTR BYTE, tablePtr:PTR BYTE, tableLen: DWORD
    Local clearBytes: DWORD
    Local i:DWORD

    ; ---- zero destination buffer ----
    mov eax, tableLen 
    add eax, 7              
    shr eax, 3           
    mov clearBytes, eax 

    mov edi, destPtr
    mov ecx, clearBytes

PermutateBits_ClearLoop:
    cmp ecx, 0
    je PermutateBits_ClearDone
    mov BYTE PTR [edi], 0
    inc edi 
    dec ecx
    jmp PermutateBits_ClearLoop
PermutateBits_ClearDone:

; ---- copy bits according to the table ----
    mov i, 0
PermutateBits_Loop:
    mov eax, i
    cmp eax, tableLen
    jge PermutateBits_Exit

    mov esi, tablePtr
    add esi, eax
    movzx ebx, BYTE PTR [esi]  ; ebx = source bit number (1-based)

    INVOKE GetBit, scrPtr, ebx  ; eax holds bit value previously read

    mov edx, i
    inc edx                             ;destinatino bit number = i + 1
    INVOKE SetBit, destPtr, edx, eax

    mov eax, i
    inc eax
    mov i, eax
    jmp PermutateBits_Loop

PermutateBits_Exit:
    ret
PermutateBits ENDP
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
;ExtractBits28(value, bitNumber) -> eax = 0 or 1
;value is 28-bit quantity stored RIGHT-justified in 32-bit (dword)
;bitNumber is 1-based, MSB-first wth bit 1 = bit 27 of value

ExtractBits28 PROC value:Dword, bitNumber:Dword
    Local shiftAmt:Dword

    mov eax, 28
    sub eax, bitNumber
    mov shiftAmt, eax

    mov eax, value
    mov ecx, shiftAmt
    shr eax, cl
    and eax, 1
    ret
ExtractBits28 ENDP
;-------------------------------------------------------------------------------

;-------------------------------------------------------------------------------
;RotateLeft28(value, shiftCount) -> eax = rotated value
;circular left shift of a 28-bit  (shiftCount is 1 or 2 for DES)

RotateLeft28 PROC value:Dword, shiftCount:Dword
    Local leftPart: Dword
    Local rightPart: Dword
    Local rightShitAmt: Dword

    mov eax, 28
    sub eax, shiftCount
    mov rightShiftAmt, eax

    mov eax, value
    mov ecx, shiftCount
    shl eax, cl
    mov leftPart, eax

    mov eax,value
    mov ecx, rightShiftAmt
    shr eax, cl
    mov rightPart, eax

    mov eax, leftPart
    or eax, rightPart
    and eax, 0FFFFFFFh          ;keep only low 28 bits
    ret
RotateLeft28 ENDP
;-------------------------------------------------------------------------------
