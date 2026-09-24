; =========================================================
; Test_C.asm
; Module C - DES Core Test Harness
;
; Link with:
;   ModuleB.obj
;   ModuleC.obj
;   Test_C.obj
;
; Tests:
;   TEST 1 : DES Encryption
;   TEST 2 : DES Decryption
;   TEST 3 : PKCS#7 Padding - 7 bytes
;   TEST 4 : PKCS#7 Padding - 8 bytes
;   TEST 5 : PKCS#7 Padding - 9 bytes
;   TEST 6 : ECB Encrypt -> Decrypt
;
; =========================================================

.386
.model flat, stdcall
option casemap:none

; =========================================================
; Irvine32
; =========================================================

INCLUDE C:\Users\natch\Downloads\Irvine\Irvine\Irvine32.inc

INCLUDELIB C:\Users\natch\Downloads\Irvine\Irvine\Irvine32.lib
INCLUDELIB C:\Users\natch\Downloads\Irvine\Irvine\Kernel32.lib
INCLUDELIB C:\Users\natch\Downloads\Irvine\Irvine\User32.lib


; =========================================================
; MODULE C PUBLIC PROCEDURES
; =========================================================

DESEncryptBlock PROTO :PTR BYTE, :PTR BYTE, :PTR BYTE
DESDecryptBlock PROTO :PTR BYTE, :PTR BYTE, :PTR BYTE

PKCS7_Pad PROTO :PTR BYTE, :DWORD, :PTR BYTE, :PTR DWORD
PKCS7_Unpad PROTO :PTR BYTE, :DWORD, :PTR BYTE, :PTR DWORD

DESEncryptECB PROTO :PTR BYTE, :DWORD, :PTR BYTE, \
                              :PTR BYTE, :PTR BYTE, :PTR DWORD

DESDecryptECB PROTO :PTR BYTE, :DWORD, :PTR BYTE, \
                              :PTR BYTE, :PTR DWORD


; =========================================================
; DATA
; =========================================================

.data

; =========================================================
; General messages
; =========================================================

titleMsg BYTE 13,10
         BYTE "==========================================",13,10
         BYTE "       MODULE C - DES CORE TEST",13,10
         BYTE "==========================================",13,10
         BYTE 0

passMsg BYTE "PASS",13,10,0
failMsg BYTE "FAIL",13,10,0

expectedMsg BYTE "Expected: ",0
actualMsg   BYTE "Actual  : ",0

separator BYTE "------------------------------------------",13,10,0


; =========================================================
; TEST 1 / TEST 2
;
; Official DES test vector
;
; Plaintext  = 0123456789ABCDEF
; Key        = 133457799BBCDFF1
; Ciphertext = 85E813540F0AB405
; =========================================================

testPlaintext BYTE 01h,23h,45h,67h,89h,0ABh,0CDh,0EFh

testKey BYTE 13h,34h,57h,79h,9Bh,0BCh,0DFh,0F1h

expectedCipher BYTE 85h,0E8h,13h,54h,0Fh,0Ah,0B4h,05h

testCipher BYTE 8 DUP(0)

testDecrypted BYTE 8 DUP(0)


test1Msg BYTE 13,10
          BYTE "TEST 1 - DES ENCRYPTION",13,10
          BYTE 0

test2Msg BYTE 13,10
          BYTE "TEST 2 - DES DECRYPTION",13,10
          BYTE 0


; =========================================================
; TEST 3
;
; Input:
;   "1234567"
;
; Expected:
;   31 32 33 34 35 36 37 01
; =========================================================

test3Input BYTE "1234567"

test3Expected BYTE \
    31h,32h,33h,34h,35h,36h,37h,01h

test3Output BYTE 16 DUP(0)

test3OutputLen DWORD 0

test3Msg BYTE 13,10
          BYTE "TEST 3 - PKCS#7 PADDING - 7 BYTES",13,10
          BYTE 0


; =========================================================
; TEST 4
;
; Input:
;   "12345678"
;
; Expected:
;   31 32 33 34 35 36 37 38
;   08 08 08 08 08 08 08 08
;
; Total = 16 bytes
; =========================================================

test4Input BYTE "12345678"

test4Expected BYTE \
    31h,32h,33h,34h,35h,36h,37h,38h, \
    08h,08h,08h,08h,08h,08h,08h,08h

test4Output BYTE 24 DUP(0)

test4OutputLen DWORD 0

test4Msg BYTE 13,10
          BYTE "TEST 4 - PKCS#7 PADDING - 8 BYTES",13,10
          BYTE 0


; =========================================================
; TEST 5
;
; Input:
;   "123456789"
;
; Expected:
;   31 32 33 34 35 36 37 38 39
;   07 07 07 07 07 07 07
;
; Total = 16 bytes
; =========================================================

test5Input BYTE "123456789"

test5Expected BYTE \
    31h,32h,33h,34h,35h,36h,37h,38h,39h, \
    07h,07h,07h,07h,07h,07h,07h

test5Output BYTE 24 DUP(0)

test5OutputLen DWORD 0

test5Msg BYTE 13,10
          BYTE "TEST 5 - PKCS#7 PADDING - 9 BYTES",13,10
          BYTE 0


; =========================================================
; TEST 6
;
; Input:
;   1234567890ABCDEF
;
; Length = 16 bytes
;
; PKCS#7:
;   + 8 bytes padding
;
; Padded length = 24 bytes
;
; Encrypt -> Decrypt
;
; Expected final plaintext:
;   1234567890ABCDEF
; =========================================================

test6Input BYTE "1234567890ABCDEF"

test6Padded BYTE 32 DUP(0)

test6Cipher BYTE 32 DUP(0)

test6Plain BYTE 32 DUP(0)

test6CipherLen DWORD 0

test6PlainLen DWORD 0

test6Expected BYTE "1234567890ABCDEF"

test6Msg BYTE 13,10
          BYTE "TEST 6 - ECB ENCRYPT / DECRYPT",13,10
          BYTE 0


; =========================================================
; Counters
; =========================================================

passCount DWORD 0
failCount DWORD 0


; =========================================================
; Final summary messages
; =========================================================

summaryMsg BYTE 13,10
           BYTE "==========================================",13,10
           BYTE "              TEST SUMMARY",13,10
           BYTE "==========================================",13,10
           BYTE 0

passCountMsg BYTE "PASS count: ",0
failCountMsg BYTE "FAIL count: ",0

allPassMsg BYTE 13,10
           BYTE "ALL TESTS PASSED.",13,10
           BYTE 0

someFailMsg BYTE 13,10
            BYTE "SOME TESTS FAILED.",13,10
            BYTE 0


; =========================================================
; CODE
; =========================================================

.code


; =========================================================
; PrintHexBytes
;
; Input:
;   ESI = address
;   ECX = number of bytes
;
; Output:
;   Prints:
;   XX XX XX XX ...
; =========================================================

PrintHexBytes PROC uses eax ecx esi

    cmp ecx, 0
    je PrintHexDone

PrintHexLoop:

    movzx eax, BYTE PTR [esi]

    call WriteHexB

    mov al, ' '
    call WriteChar

    inc esi
    dec ecx

    cmp ecx, 0
    jne PrintHexLoop

PrintHexDone:

    call Crlf

    ret

PrintHexBytes ENDP


; =========================================================
; CompareBytes
;
; Input:
;   ESI = actual
;   EDI = expected
;   ECX = number of bytes
;
; Output:
;   EAX = 1 if equal
;   EAX = 0 if different
; =========================================================

CompareBytes PROC uses ebx ecx esi edi

    mov eax, 1

    cmp ecx, 0
    je CompareDone

CompareLoop:

    mov bl, BYTE PTR [esi]

    cmp bl, BYTE PTR [edi]

    jne CompareNotEqual

    inc esi
    inc edi

    dec ecx

    cmp ecx, 0
    jne CompareLoop

    jmp CompareDone


CompareNotEqual:

    mov eax, 0


CompareDone:

    ret

CompareBytes ENDP


; =========================================================
; PrintPassFail
;
; Input:
;   EAX = 1 -> PASS
;   EAX = 0 -> FAIL
;
; Also updates passCount / failCount
; =========================================================

PrintPassFail PROC

    cmp eax, 1
    jne PrintFail

    inc passCount

    mov edx, OFFSET passMsg
    call WriteString

    ret


PrintFail:

    inc failCount

    mov edx, OFFSET failMsg
    call WriteString

    ret

PrintPassFail ENDP


; =========================================================
; TEST 1
;
; DES Encryption
;
; Plaintext:
;   0123456789ABCDEF
;
; Key:
;   133457799BBCDFF1
;
; Expected:
;   85E813540F0AB405
; =========================================================

Test1 PROC

    mov edx, OFFSET test1Msg
    call WriteString


    ; -----------------------------------------------------
    ; Encrypt
    ; -----------------------------------------------------

    INVOKE DESEncryptBlock, \
        ADDR testPlaintext, \
        ADDR testKey, \
        ADDR testCipher


    ; -----------------------------------------------------
    ; Print expected
    ; -----------------------------------------------------

    mov edx, OFFSET expectedMsg
    call WriteString

    mov esi, OFFSET expectedCipher
    mov ecx, 8

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Print actual
    ; -----------------------------------------------------

    mov edx, OFFSET actualMsg
    call WriteString

    mov esi, OFFSET testCipher
    mov ecx, 8

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Compare
    ; -----------------------------------------------------

    mov esi, OFFSET testCipher
    mov edi, OFFSET expectedCipher
    mov ecx, 8

    call CompareBytes

    call PrintPassFail

    ret

Test1 ENDP


; =========================================================
; TEST 2
;
; DES Decryption
;
; Cipher:
;   85E813540F0AB405
;
; Expected:
;   0123456789ABCDEF
; =========================================================

Test2 PROC

    mov edx, OFFSET test2Msg
    call WriteString


    ; -----------------------------------------------------
    ; Decrypt
    ; -----------------------------------------------------

    INVOKE DESDecryptBlock, \
        ADDR expectedCipher, \
        ADDR testKey, \
        ADDR testDecrypted


    ; -----------------------------------------------------
    ; Print expected
    ; -----------------------------------------------------

    mov edx, OFFSET expectedMsg
    call WriteString

    mov esi, OFFSET testPlaintext
    mov ecx, 8

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Print actual
    ; -----------------------------------------------------

    mov edx, OFFSET actualMsg
    call WriteString

    mov esi, OFFSET testDecrypted
    mov ecx, 8

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Compare
    ; -----------------------------------------------------

    mov esi, OFFSET testDecrypted
    mov edi, OFFSET testPlaintext
    mov ecx, 8

    call CompareBytes

    call PrintPassFail

    ret

Test2 ENDP


; =========================================================
; TEST 3
;
; PKCS#7 Pad 7 bytes
;
; "1234567"
;
; Expected:
; 31 32 33 34 35 36 37 01
; =========================================================

Test3 PROC

    mov edx, OFFSET test3Msg
    call WriteString


    ; -----------------------------------------------------
    ; Pad
    ; -----------------------------------------------------

    INVOKE PKCS7_Pad, \
        ADDR test3Input, \
        7, \
        ADDR test3Output, \
        ADDR test3OutputLen


    ; -----------------------------------------------------
    ; Print expected
    ; -----------------------------------------------------

    mov edx, OFFSET expectedMsg
    call WriteString

    mov esi, OFFSET test3Expected
    mov ecx, 8

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Print actual
    ; -----------------------------------------------------

    mov edx, OFFSET actualMsg
    call WriteString

    mov esi, OFFSET test3Output

    mov ecx, test3OutputLen

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Check length first
    ; -----------------------------------------------------

    mov eax, test3OutputLen

    cmp eax, 8

    jne Test3Fail


    ; -----------------------------------------------------
    ; Compare data
    ; -----------------------------------------------------

    mov esi, OFFSET test3Output
    mov edi, OFFSET test3Expected
    mov ecx, 8

    call CompareBytes

    cmp eax, 1
    jne Test3Fail


    ; PASS

    mov eax, 1
    call PrintPassFail

    ret


Test3Fail:

    xor eax, eax
    call PrintPassFail

    ret

Test3 ENDP


; =========================================================
; TEST 4
;
; PKCS#7 Pad 8 bytes
;
; "12345678"
;
; Expected length = 16
;
; Padding = 08 x 8
; =========================================================

Test4 PROC

    mov edx, OFFSET test4Msg
    call WriteString


    ; -----------------------------------------------------
    ; Pad
    ; -----------------------------------------------------

    INVOKE PKCS7_Pad, \
        ADDR test4Input, \
        8, \
        ADDR test4Output, \
        ADDR test4OutputLen


    ; -----------------------------------------------------
    ; Print expected
    ; -----------------------------------------------------

    mov edx, OFFSET expectedMsg
    call WriteString

    mov esi, OFFSET test4Expected
    mov ecx, 16

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Print actual
    ; -----------------------------------------------------

    mov edx, OFFSET actualMsg
    call WriteString

    mov esi, OFFSET test4Output

    mov ecx, test4OutputLen

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Check length
    ; -----------------------------------------------------

    mov eax, test4OutputLen

    cmp eax, 16

    jne Test4Fail


    ; -----------------------------------------------------
    ; Compare
    ; -----------------------------------------------------

    mov esi, OFFSET test4Output
    mov edi, OFFSET test4Expected
    mov ecx, 16

    call CompareBytes

    cmp eax, 1
    jne Test4Fail


    ; PASS

    mov eax, 1
    call PrintPassFail

    ret


Test4Fail:

    xor eax, eax
    call PrintPassFail

    ret

Test4 ENDP


; =========================================================
; TEST 5
;
; PKCS#7 Pad 9 bytes
;
; "123456789"
;
; Expected:
; 31 32 33 34 35 36 37 38 39
; 07 07 07 07 07 07 07
;
; Total = 16 bytes
; =========================================================

Test5 PROC

    mov edx, OFFSET test5Msg
    call WriteString


    ; -----------------------------------------------------
    ; Pad
    ; -----------------------------------------------------

    INVOKE PKCS7_Pad, \
        ADDR test5Input, \
        9, \
        ADDR test5Output, \
        ADDR test5OutputLen


    ; -----------------------------------------------------
    ; Print expected
    ; -----------------------------------------------------

    mov edx, OFFSET expectedMsg
    call WriteString

    mov esi, OFFSET test5Expected
    mov ecx, 16

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Print actual
    ; -----------------------------------------------------

    mov edx, OFFSET actualMsg
    call WriteString

    mov esi, OFFSET test5Output

    mov ecx, test5OutputLen

    call PrintHexBytes


    ; -----------------------------------------------------
    ; Check length
    ; -----------------------------------------------------

    mov eax, test5OutputLen

    cmp eax, 16

    jne Test5Fail


    ; -----------------------------------------------------
    ; Compare
    ; -----------------------------------------------------

    mov esi, OFFSET test5Output
    mov edi, OFFSET test5Expected
    mov ecx, 16

    call CompareBytes

    cmp eax, 1
    jne Test5Fail


    ; PASS

    mov eax, 1
    call PrintPassFail

    ret


Test5Fail:

    xor eax, eax
    call PrintPassFail

    ret

Test5 ENDP


; =========================================================
; TEST 6
;
; ECB round-trip
;
; Input:
;   1234567890ABCDEF
;
; Length:
;   16 bytes
;
; PKCS#7 adds:
;   08 x 8
;
; Cipher length:
;   24 bytes
;
; Then:
;
;   Encrypt
;      ↓
;   Decrypt
;      ↓
;   Unpad
;
; Expected plaintext:
;   1234567890ABCDEF
; =========================================================

Test6 PROC

    mov edx, OFFSET test6Msg
    call WriteString


    ; =====================================================
    ; STEP 1
    ; ECB ENCRYPT
    ; =====================================================

    INVOKE DESEncryptECB, \
        ADDR test6Input, \
        16, \
        ADDR testKey, \
        ADDR test6Padded, \
        ADDR test6Cipher, \
        ADDR test6CipherLen


    ; -----------------------------------------------------
    ; Expected cipher length = 24
    ; -----------------------------------------------------

    mov eax, test6CipherLen

    cmp eax, 24

    jne Test6Fail


    ; =====================================================
    ; STEP 2
    ; ECB DECRYPT
    ; =====================================================

    INVOKE DESDecryptECB, \
        ADDR test6Cipher, \
        test6CipherLen, \
        ADDR testKey, \
        ADDR test6Plain, \
        ADDR test6PlainLen


    ; -----------------------------------------------------
    ; Expected plaintext length = 16
    ; -----------------------------------------------------

    mov eax, test6PlainLen

    cmp eax, 16

    jne Test6Fail


    ; =====================================================
    ; STEP 3
    ; Compare plaintext
    ; =====================================================

    mov esi, OFFSET test6Plain
    mov edi, OFFSET test6Expected
    mov ecx, 16

    call CompareBytes

    cmp eax, 1

    jne Test6Fail


    ; =====================================================
    ; Print result
    ; =====================================================

    mov edx, OFFSET expectedMsg
    call WriteString

    mov esi, OFFSET test6Expected
    mov ecx, 16

    call PrintHexBytes


    mov edx, OFFSET actualMsg
    call WriteString

    mov esi, OFFSET test6Plain
    mov ecx, 16

    call PrintHexBytes


    ; PASS

    mov eax, 1
    call PrintPassFail

    ret


Test6Fail:

    ; Print actual if something failed

    mov edx, OFFSET actualMsg
    call WriteString

    mov esi, OFFSET test6Plain
    mov ecx, 16

    call PrintHexBytes

    xor eax, eax
    call PrintPassFail

    ret

Test6 ENDP


; =========================================================
; MAIN
; =========================================================

main PROC

    ; =====================================================
    ; Title
    ; =====================================================

    mov edx, OFFSET titleMsg
    call WriteString


    ; =====================================================
    ; Run TEST 1
    ; =====================================================

    call Test1


    ; =====================================================
    ; Run TEST 2
    ; =====================================================

    call Test2


    ; =====================================================
    ; Run TEST 3
    ; =====================================================

    call Test3


    ; =====================================================
    ; Run TEST 4
    ; =====================================================

    call Test4


    ; =====================================================
    ; Run TEST 5
    ; =====================================================

    call Test5


    ; =====================================================
    ; Run TEST 6
    ; =====================================================

    call Test6


    ; =====================================================
    ; SUMMARY
    ; =====================================================

    mov edx, OFFSET summaryMsg
    call WriteString


    ; -----------------------------------------------------
    ; PASS count
    ; -----------------------------------------------------

    mov edx, OFFSET passCountMsg
    call WriteString

    mov eax, passCount
    call WriteDec

    call Crlf


    ; -----------------------------------------------------
    ; FAIL count
    ; -----------------------------------------------------

    mov edx, OFFSET failCountMsg
    call WriteString

    mov eax, failCount
    call WriteDec

    call Crlf


    ; =====================================================
    ; Overall result
    ; =====================================================

    mov eax, failCount

    cmp eax, 0
    jne SomeTestsFailed


    mov edx, OFFSET allPassMsg
    call WriteString

    jmp TestFinished


SomeTestsFailed:

    mov edx, OFFSET someFailMsg
    call WriteString


TestFinished:

    call Crlf

    exit

main ENDP

END main