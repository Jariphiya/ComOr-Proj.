; =========================================================
; Module C - DES Core
; =========================================================
.386
.model flat, stdcall

option casemap:none

INCLUDE C:\Users\natch\Downloads\Irvine\Irvine\Irvine32.inc

INCLUDELIB C:\Users\natch\Downloads\Irvine\Irvine\Irvine32.lib
INCLUDELIB C:\Users\natch\Downloads\Irvine\Irvine\Kernel32.lib
INCLUDELIB C:\Users\natch\Downloads\Irvine\Irvine\User32.lib

; =========================================
; Module B external procedure/data
; =========================================

GenerateKeySchedule PROTO :PTR BYTE, :PTR BYTE

EXTERN SubKeys:BYTE


; =========================================================
; MODULE C PUBLIC INTERFACE
; =========================================================

PUBLIC DESEncryptBlock
PUBLIC DESDecryptBlock

PUBLIC PKCS7_Pad
PUBLIC PKCS7_Unpad

PUBLIC DESEncryptECB
PUBLIC DESDecryptECB

; =========================================================
; INTERNAL PROCEDURES
; =========================================================

ApplySBoxes    PROTO :PTR BYTE, :PTR BYTE
Expansion      PROTO :PTR BYTE, :PTR BYTE
Xor48          PROTO :PTR BYTE, :PTR BYTE, :PTR BYTE
PermutationP   PROTO :PTR BYTE, :PTR BYTE

InverseInitialPermutation PROTO :PTR BYTE, :PTR BYTE

FeistelRound        PROTO :PTR DWORD, :PTR DWORD, :PTR BYTE
FeistelRoundDecrypt PROTO :PTR DWORD, :PTR DWORD, :PTR BYTE


; =========================================================
; DATA
; =========================================================

.data

; =========================================================
; DES Initial Permutation Table
; =========================================================

    IP_Table  BYTE 58,50,42,34,26,18,10,2
              BYTE 60,52,44,36,28,20,12,4
              BYTE 62,54,46,38,30,22,14,6
              BYTE 64,56,48,40,32,24,16,8
              BYTE 57,49,41,33,25,17,9,1
              BYTE 59,51,43,35,27,19,11,3
              BYTE 61,53,45,37,29,21,13,5
              BYTE 63,55,47,39,31,23,15,7

; =========================================================
; DES EXPANSION TABLE
; 32-bit -> 48-bit
; =========================================================
          
    E_Table BYTE 32,1,2,3,4,5
            BYTE 4,5,6,7,8,9
            BYTE 8,9,10,11,12,13
            BYTE 12,13,14,15,16,17
            BYTE 16,17,18,19,20,21
            BYTE 20,21,22,23,24,25
            BYTE 24,25,26,27,28,29
            BYTE 28,29,30,31,32,1
            
; =========================================================
; DES INVERSE INITIAL PERMUTATION TABLE
; =========================================================
        
    IP_Inv_Table BYTE 40,8,48,16,56,24,64,32
                 BYTE 39,7,47,15,55,23,63,31
                 BYTE 38,6,46,14,54,22,62,30
                 BYTE 37,5,45,13,53,21,61,29
                 BYTE 36,4,44,12,52,20,60,28
                 BYTE 35,3,43,11,51,19,59,27
                 BYTE 34,2,42,10,50,18,58,26
                 BYTE 33,1,41,9,49,17,57,25

; =========================================================
; DES S-box 1-8
; =========================================================
             
    S1_Table BYTE 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7
             BYTE 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8
             BYTE 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0
             BYTE 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
             
    S2_Table BYTE 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10
             BYTE 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5
             BYTE 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15
             BYTE 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    
    S3_Table BYTE 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8
             BYTE 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1
             BYTE 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7
             BYTE 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
         
    S4_Table BYTE 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15
             BYTE 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9
             BYTE 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4
             BYTE 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
         
    S5_Table BYTE 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9
             BYTE 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6
             BYTE 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14
             BYTE 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
         
    S6_Table BYTE 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11
             BYTE 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8
             BYTE 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6
             BYTE 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
         
    S7_Table BYTE 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1
             BYTE 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6
             BYTE 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2
             BYTE 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
        
    S8_Table BYTE 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7
             BYTE 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2
             BYTE 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8
             BYTE 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 

; =========================================================
; DES P-PERMUTATION TABLE
; =========================================================   
             
    P_Table BYTE 16,7,20,21
            BYTE 29,12,28,17
            BYTE 1,15,23,26
            BYTE 5,18,31,10
            BYTE 2,8,24,14
            BYTE 32,27,3,9
            BYTE 19,13,30,6
            BYTE 22,11,4,25   
            
            
            
; =========================================================
; Working buffers
; =========================================================
            
                  
    ipOutput BYTE 8 DUP(0) ; Initial Permutation output
    
    roundRight BYTE 4 DUP(0) ; Right half converted to MSB-first bytes
    
    roundExpanded BYTE 6 DUP(0) ; Expansion output
    
    roundXored BYTE 6 DUP(0) ; E(R) XOR K
    
    roundSboxed BYTE 4 DUP(0) ; S-Box output
    
    roundPboxed BYTE 4 DUP(0) ; P-Box output
    
    finalBlock BYTE 8 DUP(0) ; R16 || L16
    
    ; Left / Right 32-bit halves
    L0 DWORD 0
    R0 DWORD 0   
    
    ; ECB DECRYPT WORKING VARIABLES
    decryptInputPtr  DWORD ?
    decryptOutputPtr DWORD ?
    decryptBlocks    DWORD ?   
    
                                                 
; =========================================================
; CODE
; =========================================================

.code

; =========================================================
; GetBit_C
;
; Input:
;   bufferPtr = address of byte buffer
;   bitNumber = DES bit number (1-based)
;
; Output:
;   EAX = 0 or 1
;
; DES bit numbering:
;   bit 1 = MSB of byte 0
; =========================================================

GetBit_C PROC uses ebx esi, \
    bufferPtr:PTR BYTE, \
    bitNumber:DWORD

    LOCAL byteIndex:DWORD
    LOCAL bitInByte:DWORD
    LOCAL shiftAmt:DWORD

    mov eax, bitNumber
    dec eax

    mov ebx, eax

    ; byteIndex = (bitNumber - 1) / 8
    shr eax, 3
    mov byteIndex, eax

    ; bitInByte = (bitNumber - 1) MOD 8
    and ebx, 7
    mov bitInByte, ebx

    ; DES uses MSB-first
    ;
    ; bit 1 -> shift 7
    ; bit 2 -> shift 6
    ; ...
    ; bit 8 -> shift 0
    mov eax, 7
    sub eax, ebx
    mov shiftAmt, eax

    ; Point to selected byte
    mov esi, bufferPtr
    add esi, byteIndex

    ; Read byte
    movzx eax, BYTE PTR [esi]

    ; Shift selected bit to bit 0
    mov ecx, shiftAmt
    shr eax, cl

    ; Keep only selected bit
    and eax, 1

    ret

GetBit_C ENDP

; =========================================================
; SetBit_C
;
; Input:
;   bufferPtr = destination buffer
;   bitNumber = 1-based bit number
;   bitValue  = 0 or 1
; =========================================================

SetBit_C PROC uses ebx edi, \
    bufferPtr:PTR BYTE, \
    bitNumber:DWORD, \
    bitValue:DWORD

    LOCAL byteIndex:DWORD
    LOCAL bitInByte:DWORD
    LOCAL shiftAmt:DWORD
    LOCAL maskBit:DWORD

    mov eax, bitNumber
    dec eax

    mov ebx, eax

    ; byteIndex
    shr eax, 3
    mov byteIndex, eax

    ; bit inside byte
    and ebx, 7
    mov bitInByte, ebx

    ; MSB-first shift amount
    mov eax, 7
    sub eax, ebx
    mov shiftAmt, eax

    ; Point to byte
    mov edi, bufferPtr
    add edi, byteIndex

    mov ecx, shiftAmt

    ; mask = 1 << shift
    mov eax, 1
    shl eax, cl

    mov maskBit, eax

    ; Read existing byte
    movzx eax, BYTE PTR [edi]

    ; Clear selected bit
    mov ebx, maskBit
    not ebx

    and eax, ebx

    ; If bitValue != 0, set selected bit
    cmp bitValue, 0
    je SetBit_Store

    or eax, maskBit

SetBit_Store:

    mov BYTE PTR [edi], al

    ret

SetBit_C ENDP

; =========================================================
; PermuteBits_C
;
; Generic permutation routine
;
; Input:
;   srcPtr
;   destPtr
;   tablePtr
;   tableLen
;
; Example:
;   IP       = 64 output bits
;   E        = 48 output bits
;   P        = 32 output bits
; =========================================================

PermuteBits_C PROC uses ebx esi edi, \
    srcPtr:PTR BYTE, \
    destPtr:PTR BYTE, \
    tablePtr:PTR BYTE, \
    tableLen:DWORD

    LOCAL clearBytes:DWORD
    LOCAL i:DWORD

    ; -----------------------------------------------------
    ; Calculate destination byte size
    ;
    ; clearBytes = ceil(tableLen / 8)
    ; -----------------------------------------------------

    mov eax, tableLen
    add eax, 7
    shr eax, 3

    mov clearBytes, eax


    ; -----------------------------------------------------
    ; Clear destination
    ; -----------------------------------------------------

    mov edi, destPtr
    mov ecx, clearBytes

ClearLoop:

    cmp ecx, 0
    je ClearDone

    mov BYTE PTR [edi], 0

    inc edi
    dec ecx

    jmp ClearLoop


ClearDone:

    ; -----------------------------------------------------
    ; i = 0
    ; -----------------------------------------------------

    mov i, 0


PermuteLoop:

    mov eax, i

    cmp eax, tableLen
    jge PermuteDone

    ; -----------------------------------------------------
    ; table[i]
    ; -----------------------------------------------------

    mov esi, tablePtr
    add esi, eax

    movzx ebx, BYTE PTR [esi]

    ; -----------------------------------------------------
    ; Read source bit specified by table[i]
    ; -----------------------------------------------------

    INVOKE GetBit_C, srcPtr, ebx

    ; EAX = source bit


    ; -----------------------------------------------------
    ; Destination bit number = i + 1
    ; -----------------------------------------------------

    mov edx, i
    inc edx

    INVOKE SetBit_C, destPtr, edx, eax


    ; -----------------------------------------------------
    ; i++
    ; -----------------------------------------------------

    mov eax, i
    inc eax
    mov i, eax

    jmp PermuteLoop


PermuteDone:

    ret

PermuteBits_C ENDP

; =========================================================
; InitialPermutation
; =========================================================

InitialPermutation PROC srcPtr:PTR BYTE, destPtr:PTR BYTE

    INVOKE PermuteBits_C, \
        srcPtr, \
        destPtr, \
        ADDR IP_Table, \
        64

    ret

InitialPermutation ENDP

; =========================================================
; Expansion
;
; 32-bit R
;     ↓
; E permutation
;     ↓
; 48-bit expanded R
; =========================================================

Expansion PROC srcPtr:PTR BYTE, destPtr:PTR BYTE

    INVOKE PermuteBits_C, \
        srcPtr, \
        destPtr, \
        ADDR E_Table, \
        48

    ret

Expansion ENDP

; =========================================================
; Xor48
;
; XOR two 48-bit values
;
; 48 bits = 6 bytes
; =========================================================

Xor48 PROC uses ebx ecx edx esi edi, \
    src1Ptr:PTR BYTE, \
    src2Ptr:PTR BYTE, \
    destPtr:PTR BYTE

    mov esi, src1Ptr
    mov edi, src2Ptr
    mov ebx, destPtr

    mov ecx, 6


XorLoop:

    mov al, BYTE PTR [esi]
    mov dl, BYTE PTR [edi]

    xor al, dl

    mov BYTE PTR [ebx], al

    inc esi
    inc edi
    inc ebx

    loop XorLoop

    ret

Xor48 ENDP

; =========================================================
; SBoxLookup
;
; Input:
;   sixBits  = 6-bit value
;   tablePtr = selected S-box
;
; DES:
;
;   b1 b2 b3 b4 b5 b6
;   │              │
;   └──── row ─────┘
;
;   b2 b3 b4 b5 = column
;
; Output:
;   EAX = 4-bit S-box value
; =========================================================

SBoxLookup PROC sixBits:DWORD, tablePtr:PTR BYTE

    push ebx
    push ecx
    push edx
    push esi

    ; -----------------------------------------------------
    ; EAX = input 6 bits
    ; -----------------------------------------------------

    mov eax, sixBits
    mov ebx, eax


    ; -----------------------------------------------------
    ; Calculate ROW
    ;
    ; row = first bit + last bit
    ; -----------------------------------------------------

    mov edx, eax

    ; Keep bit 5 (first bit of 6-bit value)
    and edx, 20h

    ; Move bit 5 to bit 1
    shr edx, 4

    ; Keep last bit
    mov ecx, eax
    and ecx, 01h

    ; Combine
    or edx, ecx

    ; EDX = row


    ; -----------------------------------------------------
    ; Calculate COLUMN
    ;
    ; middle four bits
    ; -----------------------------------------------------

    mov ecx, ebx
    shr ecx, 1
    and ecx, 0Fh

    ; ECX = column


    ; -----------------------------------------------------
    ; index = row * 16 + column
    ; -----------------------------------------------------

    shl edx, 4
    add edx, ecx


    ; -----------------------------------------------------
    ; Read S-box value
    ; -----------------------------------------------------

    mov esi, tablePtr
    add esi, edx

    movzx eax, BYTE PTR [esi]


    pop esi
    pop edx
    pop ecx
    pop ebx

    ret

SBoxLookup ENDP

; =========================================================
; Get6Bits
;
; Read six consecutive bits from source
;
; startBit = first bit number
;
; Example:
;   startBit = 1  -> bits 1..6
;   startBit = 7  -> bits 7..12
; =========================================================

Get6Bits PROC srcPtr:PTR BYTE, startBit:DWORD

    LOCAL result:DWORD
    LOCAL bitNum:DWORD
    LOCAL count:DWORD

    push ebx
    push ecx
    push edx
    push esi

    mov result, 0

    mov eax, startBit
    mov bitNum, eax

    mov count, 6


Get6Loop:

    ; -----------------------------------------------------
    ; Read one bit
    ; EAX = 0 or 1
    ; -----------------------------------------------------

    INVOKE GetBit_C, srcPtr, bitNum


    ; -----------------------------------------------------
    ; result = (result << 1) | bit
    ; -----------------------------------------------------

    mov edx, result
    shl edx, 1
    or edx, eax

    mov result, edx


    ; -----------------------------------------------------
    ; bitNum++
    ; -----------------------------------------------------

    inc bitNum


    ; -----------------------------------------------------
    ; count--
    ; -----------------------------------------------------

    mov eax, count
    dec eax
    mov count, eax

    cmp eax, 0
    jne Get6Loop


    ; -----------------------------------------------------
    ; return result
    ; -----------------------------------------------------

    mov eax, result

    pop esi
    pop edx
    pop ecx
    pop ebx

    ret

Get6Bits ENDP

; =========================================================
; ApplySBoxes
;
; Input:
;   48-bit value
;
; Process:
;
;   6-bit -> S1 -> 4-bit
;   6-bit -> S2 -> 4-bit
;   ...
;   6-bit -> S8 -> 4-bit
;
; Output:
;   32-bit value
; =========================================================

ApplySBoxes PROC srcPtr:PTR BYTE, destPtr:PTR BYTE

    LOCAL result:DWORD
    LOCAL sixBits:DWORD
    LOCAL sValue:DWORD

    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov result, 0


    ; =====================================================
    ; S1
    ; bits 1-6
    ; =====================================================

    INVOKE Get6Bits, srcPtr, 1
    mov sixBits, eax

    INVOKE SBoxLookup, sixBits, ADDR S1_Table
    mov sValue, eax

    mov eax, result
    shl eax, 4
    or eax, sValue
    mov result, eax


    ; =====================================================
    ; S2
    ; bits 7-12
    ; =====================================================

    INVOKE Get6Bits, srcPtr, 7
    mov sixBits, eax

    INVOKE SBoxLookup, sixBits, ADDR S2_Table
    mov sValue, eax

    mov eax, result
    shl eax, 4
    or eax, sValue
    mov result, eax


    ; =====================================================
    ; S3
    ; bits 13-18
    ; =====================================================

    INVOKE Get6Bits, srcPtr, 13
    mov sixBits, eax

    INVOKE SBoxLookup, sixBits, ADDR S3_Table
    mov sValue, eax

    mov eax, result
    shl eax, 4
    or eax, sValue
    mov result, eax


    ; =====================================================
    ; S4
    ; bits 19-24
    ; =====================================================

    INVOKE Get6Bits, srcPtr, 19
    mov sixBits, eax

    INVOKE SBoxLookup, sixBits, ADDR S4_Table
    mov sValue, eax

    mov eax, result
    shl eax, 4
    or eax, sValue
    mov result, eax


    ; =====================================================
    ; S5
    ; bits 25-30
    ; =====================================================

    INVOKE Get6Bits, srcPtr, 25
    mov sixBits, eax

    INVOKE SBoxLookup, sixBits, ADDR S5_Table
    mov sValue, eax

    mov eax, result
    shl eax, 4
    or eax, sValue
    mov result, eax


    ; =====================================================
    ; S6
    ; bits 31-36
    ; =====================================================

    INVOKE Get6Bits, srcPtr, 31
    mov sixBits, eax

    INVOKE SBoxLookup, sixBits, ADDR S6_Table
    mov sValue, eax

    mov eax, result
    shl eax, 4
    or eax, sValue
    mov result, eax


    ; =====================================================
    ; S7
    ; bits 37-42
    ; =====================================================

    INVOKE Get6Bits, srcPtr, 37
    mov sixBits, eax

    INVOKE SBoxLookup, sixBits, ADDR S7_Table
    mov sValue, eax

    mov eax, result
    shl eax, 4
    or eax, sValue
    mov result, eax


    ; =====================================================
    ; S8
    ; bits 43-48
    ; =====================================================

    INVOKE Get6Bits, srcPtr, 43
    mov sixBits, eax

    INVOKE SBoxLookup, sixBits, ADDR S8_Table
    mov sValue, eax

    mov eax, result
    shl eax, 4
    or eax, sValue
    mov result, eax


    ; =====================================================
    ; Store 32-bit result as MSB-first bytes
    ; =====================================================

    mov edi, destPtr

    mov eax, result

    mov ebx, eax
    shr ebx, 24
    mov BYTE PTR [edi], bl

    mov ebx, eax
    shr ebx, 16
    mov BYTE PTR [edi+1], bl

    mov ebx, eax
    shr ebx, 8
    mov BYTE PTR [edi+2], bl

    mov BYTE PTR [edi+3], al


    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx

    ret

ApplySBoxes ENDP

; =========================================================
; Permutation P
; =========================================================

PermutationP PROC srcPtr:PTR BYTE, destPtr:PTR BYTE

    INVOKE PermuteBits_C, \
        srcPtr, \
        destPtr, \
        ADDR P_Table, \
        32

    ret

PermutationP ENDP

FeistelRound PROC leftPtr:PTR DWORD, \
                     rightPtr:PTR DWORD, \
                     keyPtr:PTR BYTE

    LOCAL oldLeft:DWORD
    LOCAL oldRight:DWORD

    push ebx
    push ecx
    push edx
    push esi
    push edi


    ; =====================================================
    ; Save L0
    ; =====================================================

    mov esi, leftPtr
    mov eax, DWORD PTR [esi]
    mov oldLeft, eax


    ; =====================================================
    ; Save R0
    ; =====================================================

    mov esi, rightPtr
    mov eax, DWORD PTR [esi]
    mov oldRight, eax


    ; =====================================================
    ; Convert R0 DWORD -> MSB-first BYTE[4]
    ; =====================================================

    mov eax, oldRight
    mov esi, OFFSET roundRight

    mov ebx, eax
    shr ebx, 24
    mov BYTE PTR [esi], bl

    mov ebx, eax
    shr ebx, 16
    mov BYTE PTR [esi+1], bl

    mov ebx, eax
    shr ebx, 8
    mov BYTE PTR [esi+2], bl

    mov BYTE PTR [esi+3], al


    ; =====================================================
    ; 1. Expansion
    ; =====================================================

    INVOKE Expansion, \
        ADDR roundRight, \
        ADDR roundExpanded


    ; =====================================================
    ; 2. XOR with round key
    ; =====================================================

    INVOKE Xor48, \
        ADDR roundExpanded, \
        keyPtr, \
        ADDR roundXored


    ; =====================================================
    ; 3. S-Boxes
    ; =====================================================

    INVOKE ApplySBoxes, \
        ADDR roundXored, \
        ADDR roundSboxed


    ; =====================================================
    ; 4. P-Box
    ; =====================================================

    INVOKE PermutationP, \
        ADDR roundSboxed, \
        ADDR roundPboxed


    ; =====================================================
    ; Convert 4-byte F result to DWORD
    ; =====================================================

    mov esi, OFFSET roundPboxed

    movzx eax, BYTE PTR [esi]
    shl eax, 24

    movzx ebx, BYTE PTR [esi+1]
    shl ebx, 16
    or eax, ebx

    movzx ebx, BYTE PTR [esi+2]
    shl ebx, 8
    or eax, ebx

    movzx ebx, BYTE PTR [esi+3]
    or eax, ebx

    ; EAX = F(R0,K)

    mov edx, eax


    ; =====================================================
    ; L1 = R0
    ; =====================================================

    mov eax, oldRight

    mov edi, leftPtr
    mov DWORD PTR [edi], eax


    ; =====================================================
    ; R1 = L0 XOR F
    ; =====================================================

    mov eax, oldLeft
    xor eax, edx

    mov edi, rightPtr
    mov DWORD PTR [edi], eax


    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx

    ret

FeistelRound ENDP

; =========================================================
; FeistelRoundDecrypt
;
; Reverse Feistel:
;
;   Rold = Lnew
;   Lold = Rnew XOR F(Lnew,K)
; =========================================================

FeistelRoundDecrypt PROC uses eax ebx ecx edx esi edi, \
    LPtr:PTR DWORD, \
    RPtr:PTR DWORD, \
    subKeyPtr:PTR BYTE

    LOCAL oldL:DWORD
    LOCAL oldR:DWORD
    LOCAL fValue:DWORD


    ; =====================================================
    ; Save old L / R
    ; =====================================================

    mov esi, LPtr
    mov eax, DWORD PTR [esi]
    mov oldL, eax

    mov edi, RPtr
    mov eax, DWORD PTR [edi]
    mov oldR, eax


    ; =====================================================
    ; Convert oldL DWORD to MSB-first BYTE[4]
    ; =====================================================

    mov eax, oldL

    mov esi, OFFSET roundRight

    mov ebx, eax
    shr ebx, 24
    mov BYTE PTR [esi], bl

    mov ebx, eax
    shr ebx, 16
    mov BYTE PTR [esi+1], bl

    mov ebx, eax
    shr ebx, 8
    mov BYTE PTR [esi+2], bl

    mov BYTE PTR [esi+3], al


    ; =====================================================
    ; F(oldL, key)
    ; =====================================================

    INVOKE Expansion, \
        ADDR roundRight, \
        ADDR roundExpanded

    INVOKE Xor48, \
        ADDR roundExpanded, \
        subKeyPtr, \
        ADDR roundXored

    INVOKE ApplySBoxes, \
        ADDR roundXored, \
        ADDR roundSboxed

    INVOKE PermutationP, \
        ADDR roundSboxed, \
        ADDR roundPboxed


    ; =====================================================
    ; Convert P result BYTE[4] -> DWORD
    ; =====================================================

    mov esi, OFFSET roundPboxed

    movzx eax, BYTE PTR [esi]
    shl eax, 24

    movzx ebx, BYTE PTR [esi+1]
    shl ebx, 16
    or eax, ebx

    movzx ebx, BYTE PTR [esi+2]
    shl ebx, 8
    or eax, ebx

    movzx ebx, BYTE PTR [esi+3]
    or eax, ebx

    mov fValue, eax


    ; =====================================================
    ; Reverse Feistel
    ;
    ; Rold = Lnew
    ; Lold = Rnew XOR F(Lnew,K)
    ; =====================================================

    ; Rold = Lnew
    mov esi, RPtr

    mov eax, oldL
    mov DWORD PTR [esi], eax


    ; Lold = Rnew XOR F
    mov esi, LPtr

    mov eax, oldR
    xor eax, fValue

    mov DWORD PTR [esi], eax

    ret

FeistelRoundDecrypt ENDP

; =========================================================
; InverseInitialPermutation
; =========================================================

InverseInitialPermutation PROC srcPtr:PTR BYTE, \
                                   destPtr:PTR BYTE

    INVOKE PermuteBits_C, \
        srcPtr, \
        destPtr, \
        ADDR IP_Inv_Table, \
        64

    ret

InverseInitialPermutation ENDP

; =========================================================
; DESEncryptBlock
;
; Input:
;   plainPtr  = 8-byte plaintext
;   keyPtr    = 8-byte DES key
;
; Output:
;   cipherPtr = 8-byte ciphertext
;
; Flow:
;
;   Key Schedule
;       ↓
;   IP
;       ↓
;   L0 / R0
;       ↓
;   16 Feistel rounds
;       ↓
;   R16 || L16
;       ↓
;   Inverse IP
;       ↓
;   Ciphertext
; =========================================================

DESEncryptBlock PROC uses ebx ecx esi edi, \
    plainPtr:PTR BYTE, \
    keyPtr:PTR BYTE, \
    cipherPtr:PTR BYTE


    ; =====================================================
    ; 1. Generate K1-K16
    ; =====================================================

    INVOKE GenerateKeySchedule, \
        keyPtr, \
        ADDR SubKeys


    ; =====================================================
    ; 2. Initial Permutation
    ; =====================================================

    INVOKE InitialPermutation, \
        plainPtr, \
        ADDR ipOutput


    ; =====================================================
    ; 3. Split IP output into L0 / R0
    ; =====================================================

    ; ----- L0 -----

    movzx eax, BYTE PTR ipOutput[0]
    shl eax, 24

    movzx ebx, BYTE PTR ipOutput[1]
    shl ebx, 16
    or eax, ebx

    movzx ebx, BYTE PTR ipOutput[2]
    shl ebx, 8
    or eax, ebx

    movzx ebx, BYTE PTR ipOutput[3]
    or eax, ebx

    mov L0, eax


    ; ----- R0 -----

    movzx eax, BYTE PTR ipOutput[4]
    shl eax, 24

    movzx ebx, BYTE PTR ipOutput[5]
    shl ebx, 16
    or eax, ebx

    movzx ebx, BYTE PTR ipOutput[6]
    shl ebx, 8
    or eax, ebx

    movzx ebx, BYTE PTR ipOutput[7]
    or eax, ebx

    mov R0, eax


    ; =====================================================
    ; 4. 16 Feistel rounds
    ; =====================================================

    mov ecx, 16
    mov esi, OFFSET SubKeys


RoundLoop_Encrypt:

    INVOKE FeistelRound, \
        ADDR L0, \
        ADDR R0, \
        esi

    ; Each DES subkey = 48 bits = 6 bytes
    add esi, 6

    dec ecx
    cmp ecx, 0
    jne RoundLoop_Encrypt


    ; =====================================================
    ; 5. Final swap
    ;
    ; DES uses R16 || L16
    ; =====================================================

    ; ----- R16 -> finalBlock[0..3] -----

    mov eax, R0

    mov ebx, eax
    shr ebx, 24
    mov BYTE PTR finalBlock[0], bl

    mov ebx, eax
    shr ebx, 16
    mov BYTE PTR finalBlock[1], bl

    mov ebx, eax
    shr ebx, 8
    mov BYTE PTR finalBlock[2], bl

    mov BYTE PTR finalBlock[3], al


    ; ----- L16 -> finalBlock[4..7] -----

    mov eax, L0

    mov ebx, eax
    shr ebx, 24
    mov BYTE PTR finalBlock[4], bl

    mov ebx, eax
    shr ebx, 16
    mov BYTE PTR finalBlock[5], bl

    mov ebx, eax
    shr ebx, 8
    mov BYTE PTR finalBlock[6], bl

    mov BYTE PTR finalBlock[7], al


    ; =====================================================
    ; 6. Inverse Initial Permutation
    ; =====================================================

    INVOKE InverseInitialPermutation, \
        ADDR finalBlock, \
        cipherPtr

    ret

DESEncryptBlock ENDP

; =========================================================
; DESDecryptBlock
;
; Input:
;   cipherPtr = 8-byte ciphertext
;   keyPtr    = 8-byte DES key
;
; Output:
;   plainPtr = 8-byte plaintext
;
; Key order:
;
;   K16 -> K15 -> ... -> K1
; =========================================================

DESDecryptBlock PROC uses ebx ecx esi edi, \
    cipherPtr:PTR BYTE, \
    keyPtr:PTR BYTE, \
    plainPtr:PTR BYTE


    ; =====================================================
    ; 1. Generate K1-K16
    ; =====================================================

    INVOKE GenerateKeySchedule, \
        keyPtr, \
        ADDR SubKeys


    ; =====================================================
    ; 2. Initial Permutation
    ; =====================================================

    INVOKE InitialPermutation, \
        cipherPtr, \
        ADDR ipOutput


    ; =====================================================
    ; 3. Split IP output
    ;
    ; ipOutput = R16 || L16
    ;
    ; For the official vector this gives:
    ;
    ; R16 = 0A4CD995
    ; L16 = 43423234
    ; =====================================================

    ; ----- R16 -> R0 -----

    movzx eax, BYTE PTR [ipOutput]
    shl eax, 24

    movzx ebx, BYTE PTR [ipOutput+1]
    shl ebx, 16
    or eax, ebx

    movzx ebx, BYTE PTR [ipOutput+2]
    shl ebx, 8
    or eax, ebx

    movzx ebx, BYTE PTR [ipOutput+3]
    or eax, ebx

    mov R0, eax


    ; ----- L16 -> L0 -----

    movzx eax, BYTE PTR [ipOutput+4]
    shl eax, 24

    movzx ebx, BYTE PTR [ipOutput+5]
    shl ebx, 16
    or eax, ebx

    movzx ebx, BYTE PTR [ipOutput+6]
    shl ebx, 8
    or eax, ebx

    movzx ebx, BYTE PTR [ipOutput+7]
    or eax, ebx

    mov L0, eax


    ; =====================================================
    ; 4. Reverse 16 rounds
    ;
    ; Start at K16
    ;
    ; SubKey size = 6 bytes
    ;
    ; K16 offset = 15 * 6 = 90
    ; =====================================================

    mov ecx, 16

    mov esi, OFFSET SubKeys
    add esi, 90


Decrypt_Round:

    INVOKE FeistelRoundDecrypt, \
        ADDR L0, \
        ADDR R0, \
        esi

    sub esi, 6

    dec ecx

    cmp ecx, 0
    jne Decrypt_Round


    ; =====================================================
    ; 5. Rebuild block
    ;
    ; After reverse rounds:
    ;
    ; L0 / R0
    ;
    ; Need to reconstruct:
    ;
    ; L0 || R0
    ; =====================================================

    ; ----- L0 -> ipOutput[0..3] -----

    mov eax, L0

    mov ebx, eax
    shr ebx, 24
    mov BYTE PTR [ipOutput], bl

    mov ebx, eax
    shr ebx, 16
    mov BYTE PTR [ipOutput+1], bl

    mov ebx, eax
    shr ebx, 8
    mov BYTE PTR [ipOutput+2], bl

    mov BYTE PTR [ipOutput+3], al


    ; ----- R0 -> ipOutput[4..7] -----

    mov eax, R0

    mov ebx, eax
    shr ebx, 24
    mov BYTE PTR [ipOutput+4], bl

    mov ebx, eax
    shr ebx, 16
    mov BYTE PTR [ipOutput+5], bl

    mov ebx, eax
    shr ebx, 8
    mov BYTE PTR [ipOutput+6], bl

    mov BYTE PTR [ipOutput+7], al


    ; =====================================================
    ; 6. Inverse Initial Permutation
    ; =====================================================

    INVOKE InverseInitialPermutation, \
        ADDR ipOutput, \
        plainPtr

    ret

DESDecryptBlock ENDP

; =========================================================
; PKCS7_Pad
;
; DES block size = 8 bytes
;
; pad = 8 - (inputLen MOD 8)
;
; Examples:
;
; 7 bytes  -> +1
; 8 bytes  -> +8
; 9 bytes  -> +7
; 15 bytes -> +1
; 16 bytes -> +8
; =========================================================

PKCS7_Pad PROC uses ebx ecx edx esi edi, \
    inputPtr:PTR BYTE, \
    inputLen:DWORD, \
    outputPtr:PTR BYTE, \
    outputLenPtr:PTR DWORD


    ; =====================================================
    ; pad = 8 - (inputLen MOD 8)
    ; =====================================================

    mov eax, inputLen

    xor edx, edx

    mov ebx, 8

    div ebx

    mov eax, 8

    sub eax, edx

    mov ebx, eax
    ; EBX = padding count


    ; =====================================================
    ; outputLen = inputLen + padding
    ; =====================================================

    mov eax, inputLen

    add eax, ebx

    mov edi, outputLenPtr

    mov DWORD PTR [edi], eax


    ; =====================================================
    ; Copy input
    ; =====================================================

    mov esi, inputPtr
    mov edi, outputPtr
    mov ecx, inputLen


CopyLoop:

    cmp ecx, 0
    je PaddingStart

    mov al, BYTE PTR [esi]

    mov BYTE PTR [edi], al

    inc esi
    inc edi

    dec ecx

    jmp CopyLoop


    ; =====================================================
    ; Add PKCS#7 padding
    ; =====================================================

PaddingStart:

    mov ecx, ebx

    mov eax, ebx


PaddingLoop:

    mov BYTE PTR [edi], al

    inc edi

    dec ecx

    cmp ecx, 0
    jne PaddingLoop

    ret

PKCS7_Pad ENDP

; =========================================================
; PKCS7_Unpad
;
; Input:
;   inputPtr
;   inputLen
;
; Output:
;   outputPtr
;   outputLenPtr
;
; Return:
;   EAX = 1 -> valid padding
;   EAX = 0 -> invalid padding
; =========================================================

PKCS7_Unpad PROC uses ebx ecx edx esi edi, \
    inputPtr:PTR BYTE, \
    inputLen:DWORD, \
    outputPtr:PTR BYTE, \
    outputLenPtr:PTR DWORD


    ; =====================================================
    ; Input length cannot be zero
    ; =====================================================

    mov eax, inputLen

    cmp eax, 0

    je InvalidPadding


    ; =====================================================
    ; Input length must be multiple of 8
    ; =====================================================

    xor edx, edx

    mov ebx, 8

    div ebx

    cmp edx, 0

    jne InvalidPadding


    ; =====================================================
    ; Read last byte
    ; =====================================================

    mov esi, inputPtr

    mov eax, inputLen

    dec eax

    movzx ebx, BYTE PTR [esi + eax]


    ; =====================================================
    ; Padding must be 1..8
    ; =====================================================

    cmp ebx, 1
    jb InvalidPadding

    cmp ebx, 8
    ja InvalidPadding


    ; =====================================================
    ; outputLen = inputLen - padding
    ; =====================================================

    mov eax, inputLen

    sub eax, ebx

    mov edi, outputLenPtr

    mov DWORD PTR [edi], eax


    ; =====================================================
    ; Verify every padding byte
    ; =====================================================

    mov ecx, ebx

    mov esi, inputPtr

    mov eax, inputLen

    sub eax, ebx

    add esi, eax


CheckPadding:

    cmp BYTE PTR [esi], bl

    jne InvalidPadding

    inc esi

    dec ecx

    cmp ecx, 0

    jne CheckPadding


    ; =====================================================
    ; Copy data without padding
    ; =====================================================

    mov esi, inputPtr

    mov edi, outputPtr

    mov ecx, inputLen

    sub ecx, ebx


CopyUnpadded:

    cmp ecx, 0
    je UnpadDone

    mov al, BYTE PTR [esi]

    mov BYTE PTR [edi], al

    inc esi
    inc edi

    dec ecx

    jmp CopyUnpadded


UnpadDone:

    mov eax, 1

    ret


InvalidPadding:

    mov edi, outputLenPtr

    mov DWORD PTR [edi], 0

    mov eax, 0

    ret

PKCS7_Unpad ENDP

; =========================================================
; DESEncryptECB
;
; Flow:
;
;   Plaintext
;      ↓
;   PKCS#7 Pad
;      ↓
;   Block 1 -> DES Encrypt
;   Block 2 -> DES Encrypt
;   ...
;      ↓
;   Ciphertext
; =========================================================

DESEncryptECB PROC uses ebx ecx edx esi edi, \
    inputPtr:PTR BYTE, \
    inputLen:DWORD, \
    keyPtr:PTR BYTE, \
    paddedPtr:PTR BYTE, \
    cipherPtr:PTR BYTE, \
    outputLenPtr:PTR DWORD


    ; =====================================================
    ; 1. PKCS#7 padding
    ; =====================================================

    INVOKE PKCS7_Pad, \
        inputPtr, \
        inputLen, \
        paddedPtr, \
        outputLenPtr


    ; =====================================================
    ; 2. Calculate number of 8-byte blocks
    ; =====================================================

    mov esi, outputLenPtr

    mov eax, DWORD PTR [esi]

    xor edx, edx

    mov ebx, 8

    div ebx

    mov ecx, eax


    ; =====================================================
    ; 3. Set input/output pointers
    ; =====================================================

    mov esi, paddedPtr

    mov edi, cipherPtr


ECB_Encrypt_Loop:

    cmp ecx, 0
    je ECB_Encrypt_Done


    ; -----------------------------------------------------
    ; Encrypt one 8-byte block
    ; -----------------------------------------------------

    push ecx

    INVOKE DESEncryptBlock, \
        esi, \
        keyPtr, \
        edi

    pop ecx


    ; -----------------------------------------------------
    ; Move to next block
    ; -----------------------------------------------------

    add esi, 8
    add edi, 8

    dec ecx

    jmp ECB_Encrypt_Loop


ECB_Encrypt_Done:

    ret

DESEncryptECB ENDP

; =========================================================
; DESDecryptECB
;
; Flow:
;
;   Ciphertext
;      ↓
;   8-byte blocks
;      ↓
;   DES Decrypt each block
;      ↓
;   PKCS#7 Unpad
;      ↓
;   Plaintext
; =========================================================

DESDecryptECB PROC uses eax ebx ecx edx esi edi, \
    cipherPtr:PTR BYTE, \
    cipherLen:DWORD, \
    keyPtr:PTR BYTE, \
    plainPtr:PTR BYTE, \
    plainLenPtr:PTR DWORD


    ; =====================================================
    ; Ciphertext length must be multiple of 8
    ; =====================================================

    mov eax, cipherLen

    test eax, 7

    jnz ECB_Decrypt_Invalid


    ; =====================================================
    ; Calculate number of blocks
    ; =====================================================

    mov eax, cipherLen

    shr eax, 3

    mov decryptBlocks, eax


    ; =====================================================
    ; Initialize pointers
    ; =====================================================

    mov eax, cipherPtr

    mov decryptInputPtr, eax

    mov eax, plainPtr

    mov decryptOutputPtr, eax


ECB_Decrypt_Loop:

    mov eax, decryptBlocks

    cmp eax, 0

    je ECB_Decrypt_Unpad


    ; =====================================================
    ; Decrypt current block
    ; =====================================================

    INVOKE DESDecryptBlock, \
        decryptInputPtr, \
        keyPtr, \
        decryptOutputPtr


    ; =====================================================
    ; input += 8
    ; =====================================================

    mov eax, decryptInputPtr

    add eax, 8

    mov decryptInputPtr, eax


    ; =====================================================
    ; output += 8
    ; =====================================================

    mov eax, decryptOutputPtr

    add eax, 8

    mov decryptOutputPtr, eax


    ; =====================================================
    ; blocks--
    ; =====================================================

    mov eax, decryptBlocks

    dec eax

    mov decryptBlocks, eax

    jmp ECB_Decrypt_Loop


ECB_Decrypt_Unpad:

    ; =====================================================
    ; Remove PKCS#7 padding
    ;
    ; Decrypted data length = cipherLen
    ; because ECB preserves total padded size.
    ; =====================================================

    INVOKE PKCS7_Unpad, \
        plainPtr, \
        cipherLen, \
        plainPtr, \
        plainLenPtr

    ret


ECB_Decrypt_Invalid:

    ; Invalid ciphertext length
    mov edi, plainLenPtr

    mov DWORD PTR [edi], 0

    mov eax, 0

    ret

DESDecryptECB ENDP

END 