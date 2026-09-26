.386
.model flat, stdcall
option casemap:none

INCLUDE \masm32\include\Irvine32.inc ;เด่วมาแก้ขอ test แปป
INCLUDELIB \masm32\lib\Irvine32.lib

;-----------------------------------------------------------------------------
;                                 DATA SEGMENT
;-----------------------------------------------------------------------------

.DATA
;Permutation Choice 1 mapping table
PC1Table BYTE 57,49,41,33,25,17,9,1
BYTE 58,50,42,34,26,18,10,2
BYTE 59,51,43,35,27,19,11,3
BYTE 60,52,44,36,63,55,47,39
BYTE 31,23,15,7,62,54,46,38
BYTE 30,22,14,6,61,53,45,37
BYTE 29,21,13,5,28,20,12,4

PC2Table BYTE 14,17,11,24,1,5
BYTE 3,28,15,6,21,10
BYTE 23,19,12,4,26,8
BYTE 16,7,27,20,13,2
BYTE 41,52,31,37,47,55
BYTE 30,40,51,45,33,48
BYTE 44,49,39,56,34,53
BYTE 46,42,50,36,29,32

ShiftSchedule BYTE 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1

; ------------------------------ Test data ---------------------------------
TestKey  BYTE 013h,034h,057h,079h,09Bh,0BCh,0DFh,0F1h
SubKeys  BYTE 96 DUP(0)          ; 16 rounds * 6 bytes = 96 bytes

KLabel   BYTE "K",0
EqLabel  BYTE " = ",0
HexDigits BYTE "0123456789ABCDEF"
SpaceChar BYTE " ",0
;----------------------------------------------------------------------------

;-----------------------------------------------------------------------------
;                               CODE SEGMENT
;-----------------------------------------------------------------------------

.CODE
;-------------------------------------------------------------------------------
PUBLIC GetBit
Public SetBit
Public PC1Table, PC2Table, ShiftSchedule
;-------------------------------------------------------------------------------


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
    Local rightShiftAmt: Dword

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

;-------------------------------------------------------------------------------
;BuildCD0(keyPtr, cOutPtr, dOutptr)
;Applies PC-1 to the 64-bit key and splits the 56-bit result into C0 an D0 (each right-justified 28 bits)

BuildCD0 PROC keyPtr: PTR BYTE, cOutPtr:PTR Dword, dOutPtr:PTR Dword
    Local pc10out[7]:BYTE
    Local cVal:Dword
    Local dVal:Dword
    Local i:Dword

    LEA edi, pc10out
    INVOKE PermutateBits, keyPtr, edi, ADDR PC1Table, 56

    ;----C0 - bits 1-28 of pc10out---
    mov cVal, 0
    mov i, 1
BuildCD0_CLoop:
    mov eax, i
    cmp eax, 29
    jge BuildCD0_CDone
    LEA edi, pc10out
    INVOKE GetBit, edi, eax
    mov ebx, cVal
    shl ebx, 1
    or ebx, eax
    mov cVal, ebx
    mov eax, i
    inc eax
    mov i, eax
    jmp BuildCD0_CLoop
BuildCD0_CDone:

;---D0 - bits 29-56 of pc10out---
    mov dVal, 0
    mov i, 29
BuildCD0_DLoop:
    mov eax, i
    cmp eax, 57
    jge BuildCD0_DDone
    LEA edi, pc10out        ;Lea -> calculates mem address and store that directly into dest. reg
    INVOKE GetBit, edi, eax
    mov ebx, dVal
    shl ebx, 1
    or ebx, eax
    mov dVal, ebx
    mov eax, i
    inc eax
    mov i, eax
    jmp BuildCD0_DLoop
BuildCD0_DDone:

    mov edi, cOutPtr
    mov eax, cVal
    mov [edi], eax
    mov edi, dOutPtr
    mov eax, dVal
    mov [edi], eax
    ret
BuildCD0 ENDP
;-------------------------------------------------------------------------------

;--------------------------------------------------------------------------------
;PackCD(Cval, dVal, destPtr)
;Packs a 28-bit C and a 28-bit D into a 56-bit buffer

PackCD PROC cVal:Dword, dVal:Dword, destPtr:PTR BYTE
    Local i:Dword
    Local bitVal:Dword
    Local localBitNum:Dword

    ;--- bits 1-28 from C ---
    mov i, 1
PackCD_CLoop:
    mov eax, i
    cmp eax, 29
    jge PackCD_CDone
    INVOKE ExtractBits28, cVal, eax
    mov bitVal, eax
    mov eax, i
    INVOKE SetBit, destPtr, eax, bitVal
    mov eax, i
    inc eax
    mov i, eax
    jmp PackCD_CLoop
PackCD_CDone:

    ;---- bits 29-56 from D ----
    mov i, 29
PackCD_DLoop: 
    mov eax, i
    cmp eax, 57
    jge PackCD_DDone
    mov eax, i
    sub eax, 28                     ; local bit position inside D (1...28)
    mov localBitNum, eax
    INVOKE ExtractBits28, dVal, localBitNum
    mov bitVal, eax
    mov eax, i
    INVOKE SetBit, destPtr, eax, bitVal
    mov eax, i
    inc eax
    mov i, eax
    jmp PackCD_DLoop
PackCD_DDone:
    ret
PackCD ENDP
;--------------------------------------------------------------------------------

;--------------------------------------------------------------------------------
;GenerateKeySchedule(keyPtr,subkeysPtr)
;keyPtr -> 8 byte DES key
;subkeysPtr -> 96 bytes (16 * 6), k1-K16 in order 

GenerateKeySchedule PROC keyPtr:PTR Byte, subkeysPtr:PTR BYTE
    Local cCurrent:Dword
    Local dCurrent:Dword
    Local cdBuffer[7]:BYTE
    Local round:Dword
    Local destOffset:Dword
    Local shiftAmt: Dword

    LEA eax, cCurrent
    LEA ebx, dCurrent
    INVOKE BuildCD0, keyPtr, eax, ebx

    mov round,1 
GenKS_Loop:
    mov eax, round
    cmp eax, 17
    jge GenKS_Done

    ;look up this round's shift amt [1/2] (table is 0 indexed)
    mov esi, Offset ShiftSchedule
    mov eax, round
    dec eax
    add esi, eax
    movzx eax, BYTE PTR[esi]
    mov shiftAmt, eax

    INVOKE RotateLeft28, cCurrent, shiftAmt
    mov cCurrent, eax
    INVOKE RotateLeft28, dCurrent, shiftAmt
    mov dCurrent, eax

    LEA edi, cdBuffer
    INVOKE PackCD, cCurrent, dCurrent, edi

    ;dest offset in subkeys array = (round - 1 ) * 6
    mov eax, round
    dec eax
    mov ebx, 6
    mul ebx
    mov destOffset, eax

    mov edi, subkeysPtr
    add edi, destOffset
    LEA esi, cdBuffer
    INVOKE PermutateBits, esi, edi, ADDR PC2Table, 48

    mov eax, round
    inc eax
    mov round, eax
    jmp GenKS_Loop

GenKS_Done:
    ret
GenerateKeySchedule ENDP 
;-------------------------------------------------------------------------------------------

;-------------------------------------------------------------------------------------------
;PrintHexByte(byteVal) -> testing helper only
;Prints exactly 2 hex digits for a value 0-255, unlike WriteHex which always
;prints a full 8-digit 32-bit value.

PrintHexByte PROC byteVal:DWORD
    mov eax, byteVal
    mov ecx, eax
    shr ecx, 4
    and ecx, 0Fh
    mov edx, OFFSET HexDigits
    add edx, ecx
    movzx eax, BYTE PTR [edx]
    call WriteChar

    mov eax, byteVal
    and eax, 0Fh
    mov edx, OFFSET HexDigits
    add edx, eax
    movzx eax, BYTE PTR [edx]
    call WriteChar
    ret
PrintHexByte ENDP
;-------------------------------------------------------------------------------------------

;-------------------------------------------------------------------------------------------
;DisplayKeySchedule(subkeysPtr) -> testing helper only
;prints K1-K16 as hex bytes, one round per line

DisplayKeySchedule PROC subkeysPtr:PTR BYTE
    Local round: Dword
    Local byteIdx: Dword
    Local rowOffset:Dword

    mov round, 1
Disp_RoundLoop:
    mov eax, round
    cmp eax, 17
    jge Disp_Done

    mov eax, round
    dec eax
    mov ebx, 6
    mul ebx
    mov rowOffset, eax

    mov edx, OFFSET KLabel
    call WriteString
    mov eax, round 
    call WriteDec
    mov edx, OFFSET EqLabel
    call WriteString

    mov byteIdx, 0
Disp_ByteLoop:
    mov eax, byteIdx
    cmp eax, 6
    jge Disp_ByteDone
    mov esi, subkeysPtr
    add esi, rowOffset
    add esi, byteIdx
    movzx eax, BYTE PTR [esi]
    INVOKE PrintHexByte, eax ;fix for printing
    mov edx, OFFSET SpaceChar
    call WriteString
    mov eax, byteIdx
    inc eax
    mov byteIdx, eax
    jmp Disp_ByteLoop
Disp_ByteDone:
    call Crlf

    mov eax, round 
    inc eax
    mov round, eax
    jmp Disp_RoundLoop
Disp_Done:
    ret
DisplayKeySchedule ENDP
;--------------------------------------------------------------------------------------

;--------------------------------------------------------------------------------------
main PROC 
    INVOKE GenerateKeySchedule, ADDR TestKey, ADDR SubKeys
    INVOKE DisplayKeySchedule, ADDR SubKeys
    INVOKE ExitProcess, 0
main ENDP 

end main