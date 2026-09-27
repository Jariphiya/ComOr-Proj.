; =====================================================================
; Reuses GetBit / PermuteBits / GenerateKeySchedule / SubKeys from Module B 
; =====================================================================

.386
.model flat, stdcall
option casemap:none

INCLUDE C:\Irvine\Irvine32.inc
INCLUDELIB C:\Irvine\Irvine32.lib
INCLUDELIB C:\Irvine\Kernel32.lib
INCLUDELIB C:\Irvine\User32.lib

; --- Imported from Module B ---
GenerateKeySchedule PROTO :PTR BYTE, :PTR BYTE
GetBit              PROTO :PTR BYTE, :DWORD
PermutateBits         PROTO :PTR BYTE, :PTR BYTE, :PTR BYTE, :DWORD
EXTERN SubKeys:BYTE

PUBLIC DESEncryptBlock, DESDecryptBlock, PKCS7_Pad, PKCS7_Unpad, DESEncryptECB, DESDecryptECB

.data
    IP_Table  BYTE 58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4
              BYTE 62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8
              BYTE 57,49,41,33,25,17,9,1,  59,51,43,35,27,19,11,3
              BYTE 61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7

    E_Table   BYTE 32,1,2,3,4,5,   4,5,6,7,8,9,     8,9,10,11,12,13
              BYTE 12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25
              BYTE 24,25,26,27,28,29, 28,29,30,31,32,1

    IP_Inv_Table BYTE 40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31
                 BYTE 38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29
                 BYTE 36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27
                 BYTE 34,2,42,10,50,18,58,26, 33,1,41,9,49,17,57,25

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

    ; lets ApplySBoxes loop over all 8 S-boxes instead of 8 copy-pasted blocks
    SBoxPtrs DWORD OFFSET S1_Table, OFFSET S2_Table, OFFSET S3_Table, OFFSET S4_Table
             DWORD OFFSET S5_Table, OFFSET S6_Table, OFFSET S7_Table, OFFSET S8_Table

    P_Table BYTE 16,7,20,21, 29,12,28,17, 1,15,23,26, 5,18,31,10
            BYTE 2,8,24,14,  32,27,3,9,   19,13,30,6, 22,11,4,25

    ipOutput      BYTE 8 DUP(0)   ; Initial Permutation output
    roundRight    BYTE 4 DUP(0)   ; half fed into f(), MSB-first bytes
    roundExpanded BYTE 6 DUP(0)   ; Expansion output
    roundXored    BYTE 6 DUP(0)   ; E(R) XOR K
    roundSboxed   BYTE 4 DUP(0)   ; S-Box output
    roundPboxed   BYTE 4 DUP(0)   ; P-Box output
    finalBlock    BYTE 8 DUP(0)   ; pre-output block, before IP-1
    L0 DWORD 0
    R0 DWORD 0
    decryptInputPtr  DWORD ?
    decryptOutputPtr DWORD ?
    decryptBlocks    DWORD ?

.code

;PackBytesToDword(srcPtr) -> EAX : reads 4 bytes MSB-first into one 32-bit value
PackBytesToDword PROC uses ebx esi srcPtr:PTR BYTE
    mov esi, srcPtr
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
    ret
PackBytesToDword ENDP

;UnpackDwordToBytes(value, destPtr) : reverse of PackBytesToDword
UnpackDwordToBytes PROC uses ebx edi value:DWORD, destPtr:PTR BYTE
    mov edi, destPtr
    mov eax, value
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
    ret
UnpackDwordToBytes ENDP

; --- thin wrappers: each just names which table PermuteBits should use ---
InitialPermutation PROC srcPtr:PTR BYTE, destPtr:PTR BYTE
    INVOKE PermutateBits, srcPtr, destPtr, ADDR IP_Table, 64
    ret
InitialPermutation ENDP

Expansion PROC srcPtr:PTR BYTE, destPtr:PTR BYTE
    INVOKE PermutateBits, srcPtr, destPtr, ADDR E_Table, 48
    ret
Expansion ENDP

PermutationP PROC srcPtr:PTR BYTE, destPtr:PTR BYTE
    INVOKE PermutateBits, srcPtr, destPtr, ADDR P_Table, 32
    ret
PermutationP ENDP

InverseInitialPermutation PROC srcPtr:PTR BYTE, destPtr:PTR BYTE
    INVOKE PermutateBits, srcPtr, destPtr, ADDR IP_Inv_Table, 64
    ret
InverseInitialPermutation ENDP

;Xor48(src1Ptr, src2Ptr, destPtr) : XORs two 6-byte (48-bit) buffers
Xor48 PROC uses ebx ecx edx esi edi src1Ptr:PTR BYTE, src2Ptr:PTR BYTE, destPtr:PTR BYTE
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

;SBoxLookup(sixBits, tablePtr) -> EAX : row=(bit1<<1)|bit6, col=middle 4 bits
SBoxLookup PROC sixBits:DWORD, tablePtr:PTR BYTE
    push ebx
    push ecx
    push edx
    push esi
    mov eax, sixBits
    mov ebx, eax
    mov edx, eax
    and edx, 20h
    shr edx, 4
    mov ecx, eax
    and ecx, 01h
    or edx, ecx
    mov ecx, ebx
    shr ecx, 1
    and ecx, 0Fh
    shl edx, 4
    add edx, ecx
    mov esi, tablePtr
    add esi, edx
    movzx eax, BYTE PTR [esi]
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret
SBoxLookup ENDP

;Get6Bits(srcPtr, startBit) -> EAX : reads 6 consecutive bits via GetBit
Get6Bits PROC srcPtr:PTR BYTE, startBit:DWORD
    LOCAL result:DWORD, bitNum:DWORD, count:DWORD
    push ebx
    push ecx
    push edx
    push esi
    mov result, 0
    mov eax, startBit
    mov bitNum, eax
    mov count, 6
Get6Loop:
    INVOKE GetBit, srcPtr, bitNum
    mov edx, result
    shl edx, 1
    or edx, eax
    mov result, edx
    mov eax, bitNum
    inc eax
    mov bitNum, eax
    mov eax, count
    dec eax
    mov count, eax
    cmp eax, 0
    jne Get6Loop
    mov eax, result
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret
Get6Bits ENDP

;ApplySBoxes(srcPtr, destPtr) : loops over SBoxPtrs instead of 8 copy-pasted blocks
ApplySBoxes PROC uses ebx ecx edx esi edi srcPtr:PTR BYTE, destPtr:PTR BYTE
    LOCAL result:DWORD, sixBits:DWORD, startBit:DWORD, i:DWORD
    mov result, 0
    mov startBit, 1
    mov i, 0
SBoxLoop:
    mov eax, i
    cmp eax, 8
    jge SBoxDone
    INVOKE Get6Bits, srcPtr, startBit
    mov sixBits, eax
    mov eax, i
    mov edx, SBoxPtrs[eax*4]
    INVOKE SBoxLookup, sixBits, edx
    mov ebx, result
    shl ebx, 4
    or ebx, eax
    mov result, ebx
    mov eax, startBit
    add eax, 6
    mov startBit, eax
    mov eax, i
    inc eax
    mov i, eax
    jmp SBoxLoop
SBoxDone:
    INVOKE UnpackDwordToBytes, result, destPtr
    ret
ApplySBoxes ENDP

;FeistelRound(leftPtr, rightPtr, keyPtr) : L' = R, R' = L XOR f(R,K)
FeistelRound PROC uses ebx ecx edx esi edi leftPtr:PTR DWORD, rightPtr:PTR DWORD, keyPtr:PTR BYTE
    LOCAL oldLeft:DWORD, oldRight:DWORD, fResult:DWORD
    mov esi, leftPtr
    mov eax, DWORD PTR [esi]
    mov oldLeft, eax
    mov esi, rightPtr
    mov eax, DWORD PTR [esi]
    mov oldRight, eax

    INVOKE UnpackDwordToBytes, oldRight, ADDR roundRight
    INVOKE Expansion, ADDR roundRight, ADDR roundExpanded
    INVOKE Xor48, ADDR roundExpanded, keyPtr, ADDR roundXored
    INVOKE ApplySBoxes, ADDR roundXored, ADDR roundSboxed
    INVOKE PermutationP, ADDR roundSboxed, ADDR roundPboxed
    INVOKE PackBytesToDword, ADDR roundPboxed
    mov fResult, eax

    mov edi, leftPtr
    mov eax, oldRight
    mov DWORD PTR [edi], eax
    mov edi, rightPtr
    mov eax, oldLeft
    xor eax, fResult
    mov DWORD PTR [edi], eax
    ret
FeistelRound ENDP

;FeistelRoundDecrypt(LPtr, RPtr, subKeyPtr) : mirrors FeistelRound in reverse -
;decrypt treats the block as R16L16, so f() is fed oldL here, not oldR.
FeistelRoundDecrypt PROC uses ebx ecx edx esi edi LPtr:PTR DWORD, RPtr:PTR DWORD, subKeyPtr:PTR BYTE
    LOCAL oldL:DWORD, oldR:DWORD, fValue:DWORD
    mov esi, LPtr
    mov eax, DWORD PTR [esi]
    mov oldL, eax
    mov edi, RPtr
    mov eax, DWORD PTR [edi]
    mov oldR, eax

    INVOKE UnpackDwordToBytes, oldL, ADDR roundRight
    INVOKE Expansion, ADDR roundRight, ADDR roundExpanded
    INVOKE Xor48, ADDR roundExpanded, subKeyPtr, ADDR roundXored
    INVOKE ApplySBoxes, ADDR roundXored, ADDR roundSboxed
    INVOKE PermutationP, ADDR roundSboxed, ADDR roundPboxed
    INVOKE PackBytesToDword, ADDR roundPboxed
    mov fValue, eax

    mov esi, RPtr
    mov eax, oldL
    mov DWORD PTR [esi], eax
    mov esi, LPtr
    mov eax, oldR
    xor eax, fValue
    mov DWORD PTR [esi], eax
    ret
FeistelRoundDecrypt ENDP

;DESEncryptBlock(plainPtr, keyPtr, cipherPtr) : one 8-byte block
DESEncryptBlock PROC uses ebx ecx esi edi plainPtr:PTR BYTE, keyPtr:PTR BYTE, cipherPtr:PTR BYTE
    INVOKE GenerateKeySchedule, keyPtr, ADDR SubKeys
    INVOKE InitialPermutation, plainPtr, ADDR ipOutput
    INVOKE PackBytesToDword, OFFSET ipOutput
    mov L0, eax
    INVOKE PackBytesToDword, OFFSET ipOutput+4
    mov R0, eax

    mov ecx, 16
    mov esi, OFFSET SubKeys
RoundLoop_Encrypt:
    INVOKE FeistelRound, ADDR L0, ADDR R0, esi
    add esi, 6
    dec ecx
    jnz RoundLoop_Encrypt

    ; pre-output is R16 || L16 (final swap folded in here)
    INVOKE UnpackDwordToBytes, R0, OFFSET finalBlock
    INVOKE UnpackDwordToBytes, L0, OFFSET finalBlock+4
    INVOKE InverseInitialPermutation, ADDR finalBlock, cipherPtr
    ret
DESEncryptBlock ENDP

;DESDecryptBlock(cipherPtr, keyPtr, plainPtr) : same network, subkeys reversed
DESDecryptBlock PROC uses ebx ecx esi edi cipherPtr:PTR BYTE, keyPtr:PTR BYTE, plainPtr:PTR BYTE
    INVOKE GenerateKeySchedule, keyPtr, ADDR SubKeys
    INVOKE InitialPermutation, cipherPtr, ADDR ipOutput
    ; per FIPS decrypt convention, treat input as R16||L16
    INVOKE PackBytesToDword, OFFSET ipOutput
    mov R0, eax
    INVOKE PackBytesToDword, OFFSET ipOutput+4
    mov L0, eax

    mov ecx, 16
    mov esi, OFFSET SubKeys
    add esi, 90              ; start at K16, step backwards to K1
Decrypt_Round:
    INVOKE FeistelRoundDecrypt, ADDR L0, ADDR R0, esi
    sub esi, 6
    dec ecx
    jnz Decrypt_Round

    ; pre-output is L0 || R0 - no extra swap needed here
    INVOKE UnpackDwordToBytes, L0, OFFSET ipOutput
    INVOKE UnpackDwordToBytes, R0, OFFSET ipOutput+4
    INVOKE InverseInitialPermutation, ADDR ipOutput, plainPtr
    ret
DESDecryptBlock ENDP

;PKCS7_Pad(inputPtr, inputLen, outputPtr, outputLenPtr) : byte-copy logic, unchanged
PKCS7_Pad PROC uses ebx ecx edx esi edi inputPtr:PTR BYTE, inputLen:DWORD, outputPtr:PTR BYTE, outputLenPtr:PTR DWORD
    mov eax, inputLen
    xor edx, edx
    mov ebx, 8
    div ebx
    mov eax, 8
    sub eax, edx
    mov ebx, eax
    mov eax, inputLen
    add eax, ebx
    mov edi, outputLenPtr
    mov DWORD PTR [edi], eax
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

;PKCS7_Unpad(inputPtr, inputLen, outputPtr, outputLenPtr) -> EAX (1=ok, 0=bad)
PKCS7_Unpad PROC uses ebx ecx edx esi edi inputPtr:PTR BYTE, inputLen:DWORD, outputPtr:PTR BYTE, outputLenPtr:PTR DWORD
    mov eax, inputLen
    cmp eax, 0
    je InvalidPadding
    xor edx, edx
    mov ebx, 8
    div ebx
    cmp edx, 0
    jne InvalidPadding
    mov esi, inputPtr
    mov eax, inputLen
    dec eax
    movzx ebx, BYTE PTR [esi + eax]
    cmp ebx, 1
    jb InvalidPadding
    cmp ebx, 8
    ja InvalidPadding
    mov eax, inputLen
    sub eax, ebx
    mov edi, outputLenPtr
    mov DWORD PTR [edi], eax
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

;DESEncryptECB(inputPtr, inputLen, keyPtr, paddedPtr, cipherPtr, outputLenPtr)
DESEncryptECB PROC uses ebx ecx edx esi edi inputPtr:PTR BYTE, inputLen:DWORD, keyPtr:PTR BYTE, paddedPtr:PTR BYTE, cipherPtr:PTR BYTE, outputLenPtr:PTR DWORD
    INVOKE PKCS7_Pad, inputPtr, inputLen, paddedPtr, outputLenPtr
    mov esi, outputLenPtr
    mov eax, DWORD PTR [esi]
    xor edx, edx
    mov ebx, 8
    div ebx
    mov ecx, eax
    mov esi, paddedPtr
    mov edi, cipherPtr
ECB_Encrypt_Loop:
    cmp ecx, 0
    je ECB_Encrypt_Done
    push ecx
    INVOKE DESEncryptBlock, esi, keyPtr, edi
    pop ecx
    add esi, 8
    add edi, 8
    dec ecx
    jmp ECB_Encrypt_Loop
ECB_Encrypt_Done:
    ret
DESEncryptECB ENDP

;DESDecryptECB(cipherPtr, cipherLen, keyPtr, plainPtr, plainLenPtr)
DESDecryptECB PROC uses eax ebx ecx edx esi edi cipherPtr:PTR BYTE, cipherLen:DWORD, keyPtr:PTR BYTE, plainPtr:PTR BYTE, plainLenPtr:PTR DWORD
    mov eax, cipherLen
    test eax, 7
    jnz ECB_Decrypt_Invalid
    mov eax, cipherLen
    shr eax, 3
    mov decryptBlocks, eax
    mov eax, cipherPtr
    mov decryptInputPtr, eax
    mov eax, plainPtr
    mov decryptOutputPtr, eax
ECB_Decrypt_Loop:
    mov eax, decryptBlocks
    cmp eax, 0
    je ECB_Decrypt_Unpad
    INVOKE DESDecryptBlock, decryptInputPtr, keyPtr, decryptOutputPtr
    mov eax, decryptInputPtr
    add eax, 8
    mov decryptInputPtr, eax
    mov eax, decryptOutputPtr
    add eax, 8
    mov decryptOutputPtr, eax
    mov eax, decryptBlocks
    dec eax
    mov decryptBlocks, eax
    jmp ECB_Decrypt_Loop
ECB_Decrypt_Unpad:
    INVOKE PKCS7_Unpad, plainPtr, cipherLen, plainPtr, plainLenPtr
    ret
ECB_Decrypt_Invalid:
    mov edi, plainLenPtr
    mov DWORD PTR [edi], 0
    mov eax, 0
    ret
DESDecryptECB ENDP

END
