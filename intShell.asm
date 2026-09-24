.386
.model flat, stdcall
.stack 4096
EXTERN main@0:PROC

INCLUDE Irvine32.inc

PUBLIC RunShell, inputBuffer, argFile, keyBytes, fileBuffer, outBuffer, fileSize, outSize

; =========================================================
; Constants
; =========================================================
MAX_INPUT   EQU 256
MAX_FILE    EQU 65536
CMD_COUNT   EQU 7

; FSM states
S_GAP       EQU 0       ; between tokens (whitespace)
S_WORD      EQU 1       ; inside unquoted token
S_QARG      EQU 2       ; inside "quoted token"

.DATA
    promptIntro BYTE "=== Welcome to DES Encryption! ===", 0
    promptMenu  BYTE "--- Available Commands ---", 0Dh, 0Ah
                BYTE "KEYGEN  <key>", 0Dh, 0Ah
                BYTE "ENCRYPT <file> <key>", 0Dh, 0Ah
                BYTE "DECRYPT <file> <key>", 0Dh, 0Ah
                BYTE "DUMP    <file>", 0Dh, 0Ah
                BYTE "STATS   <file>", 0Dh, 0Ah
                BYTE "CLEAR", 0Dh, 0Ah
                BYTE "EXIT", 0Dh, 0Ah
                BYTE "(key = 16 hex digits, e.g. 0x133457799BBCDFF1)", 0
    promptShell BYTE "DES-SHELL> ", 0

    ; ---- error messages ----
    errUnknown  BYTE "[-] Error: Invalid command", 0
    errQuote    BYTE "[-] Error: Missing closing quote", 0
    errTooMany  BYTE "[-] Error: Too many arguments", 0
    errMisplace BYTE "[-] Error: Misplaced quote", 0
    errArgs     BYTE "[-] Error: Wrong number of arguments", 0
    errKey      BYTE "[-] Error: Invalid key (need 16 hex digits, e.g. 0x133457799BBCDFF1)", 0
    errFile     BYTE "[-] Error: Cannot open file", 0
    errSave     BYTE "[-] Error: Cannot write output file", 0
    errCipherLen BYTE "[-] Error: Ciphertext size must be a multiple of 8 bytes", 0
    errNotReady BYTE "[!] Cipher engine (Module B/C) not connected yet - nothing written", 0

    ; ---- usage strings ----
    usKeyGen    BYTE "    Usage: KEYGEN <key>", 0
    usEn        BYTE "    Usage: ENCRYPT <file> <key>", 0
    usDe        BYTE "    Usage: DECRYPT <file> <key>", 0
    usDump      BYTE "    Usage: DUMP <file>", 0
    usStat      BYTE "    Usage: STATS <file>", 0
    usClear     BYTE "    Usage: CLEAR", 0
    usExit      BYTE "    Usage: EXIT", 0

    ; ---- info messages ----
    msgLoad     BYTE "Loading ", 0
    msgParen    BYTE " (", 0
    msgBytes    BYTE " bytes)...", 0
    msgKeyRun   BYTE "Executing DES 16-round key generation...", 0
    msgProc     BYTE "Processing ", 0
    msgBlocks   BYTE " block(s) in ECB mode...", 0
    msgEncDone  BYTE "File encrypted successfully -> ", 0
    msgDecDone  BYTE "File decrypted successfully -> ", 0
    msgKeyOk    BYTE "Key accepted (64-bit). Generating 16 subkeys...", 0
    msgBye      BYTE "Exiting DES Command-Line Shell...", 0
    sufEnc      BYTE ".enc", 0
    sufDec      BYTE ".dec", 0

    ; ---- 7 menu commands ----
    cmdKeyGen   BYTE "KEYGEN", 0
    cmdEn       BYTE "ENCRYPT", 0
    cmdDe       BYTE "DECRYPT", 0
    cmdDump     BYTE "DUMP", 0
    cmdStat     BYTE "STATS", 0
    cmdClear    BYTE "CLEAR", 0
    cmdExit     BYTE "EXIT", 0

    ; command table: [name ptr, expected arg count, usage ptr]  (12 bytes / entry)
    ; index order = KEYGEN, ENCRYPT, DECRYPT, DUMP, STATS, CLEAR, EXIT
    cmdTable    DWORD OFFSET cmdKeyGen, 1, OFFSET usKeyGen
                DWORD OFFSET cmdEn,     2, OFFSET usEn
                DWORD OFFSET cmdDe,     2, OFFSET usDe
                DWORD OFFSET cmdDump,   1, OFFSET usDump
                DWORD OFFSET cmdStat,   1, OFFSET usStat
                DWORD OFFSET cmdClear,  0, OFFSET usClear
                DWORD OFFSET cmdExit,   0, OFFSET usExit

    ; parser results: [0]=command, [1]=arg1, [2]=arg2 (pointers into inputBuffer)
    tokPtrs     DWORD 3 DUP(0)

    ; shared with other modules
    inputBuffer BYTE MAX_INPUT DUP(0)
    argFile     DWORD 0             ; pointer to current file name
    keyBytes    BYTE 8 DUP(0)       ; 64-bit key, big-endian byte order (13 34 57 79 9B BC DF F1)
    fileSize    DWORD 0             ; bytes loaded into fileBuffer
    outSize     DWORD 0             ; bytes to write from outBuffer (set by Module C)

    suffixPtr   DWORD 0
    doneMsgPtr  DWORD 0
    outName     BYTE MAX_INPUT + 8 DUP(0)

.DATA?
    fileBuffer  BYTE MAX_FILE DUP(?)
    outBuffer   BYTE MAX_FILE + 8 DUP(?)

.CODE

; =========================================================
; Procedure: RunShell (Main loop, Module A)
;   returns EAX = 0
; =========================================================
RunShell PROC
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov edx, OFFSET promptIntro
    call WriteString
    call Crlf
    mov edx, OFFSET promptMenu
    call WriteString
    call Crlf

ShellLoop:
    mov edx, OFFSET promptShell
    call WriteString

    mov edx, OFFSET inputBuffer
    mov ecx, SIZEOF inputBuffer - 1
    call ReadString
    test eax, eax
    jz ShellLoop                    ; empty line -> prompt again

    ; ---------- FSM tokenizer ----------
    push OFFSET inputBuffer
    call ParseCommandLine           ; EAX = token count, or negative error code
    cmp eax, 0
    jl ParseError
    je ShellLoop                    ; only spaces
    dec eax
    mov edi, eax                    ; EDI = actual argument count

    ; command name -> uppercase (file names keep their case)
    push DWORD PTR [tokPtrs]
    call ToUpperCase

    ; ---------- look up command ----------
    xor ebx, ebx                    ; EBX = command index
    mov esi, OFFSET cmdTable
FindCmd:
    cmp ebx, CMD_COUNT
    jae UnknownCmd
    push DWORD PTR [esi]
    push DWORD PTR [tokPtrs]
    call Str_compare                ; ZF = 1 if equal
    je FoundCmd
    add esi, 12
    inc ebx
    jmp FindCmd

FoundCmd:
    cmp edi, [esi+4]                ; check number of arguments
    jne BadUsage

    cmp ebx, 0
    je DoKeyGen
    cmp ebx, 1
    je DoEncrypt
    cmp ebx, 2
    je DoDecrypt
    cmp ebx, 3
    je DoDump
    cmp ebx, 4
    je DoStats
    cmp ebx, 5
    je DoClear
    jmp ExitShell

; ---------------------------------------------------------
; Error reporting
; ---------------------------------------------------------
UnknownCmd:
    mov edx, OFFSET errUnknown
    jmp PrintErr

BadUsage:
    mov edx, OFFSET errArgs
    call WriteString
    call Crlf
    mov edx, [esi+8]                ; usage line of that command
    jmp PrintErr

ParseError:                         ; EAX = -1 / -2 / -3
    cmp eax, -1
    mov edx, OFFSET errQuote
    je PrintErr
    cmp eax, -2
    mov edx, OFFSET errTooMany
    je PrintErr
    mov edx, OFFSET errMisplace
    jmp PrintErr

BadKey:
    mov edx, OFFSET errKey
    jmp PrintErr
BadFile:
    mov edx, OFFSET errFile
    jmp PrintErr
BadSave:
    mov edx, OFFSET errSave
    jmp PrintErr
BadCipherLen:
    mov edx, OFFSET errCipherLen
    jmp PrintErr
NotReady:
    mov edx, OFFSET errNotReady
PrintErr:
    call WriteString
    call Crlf
    jmp ShellLoop

; ---------------------------------------------------------
; Command handlers
; ---------------------------------------------------------
DoKeyGen:
    push OFFSET keyBytes
    push DWORD PTR [tokPtrs+4]
    call ParseHexKey
    test eax, eax
    jz BadKey
    mov edx, OFFSET msgKeyOk
    call WriteString
    call Crlf
    ; TODO (Module B): push OFFSET keyBytes / call KeyGen  -> prints K1..K16
    jmp ShellLoop

DoEncrypt:
    push OFFSET keyBytes
    push DWORD PTR [tokPtrs+8]
    call ParseHexKey
    test eax, eax
    jz BadKey

    mov eax, [tokPtrs+4]
    mov argFile, eax
    push MAX_FILE
    push OFFSET fileBuffer
    push argFile
    call LoadFile                   ; EAX = bytes read or -1
    cmp eax, -1
    je BadFile
    mov fileSize, eax

    mov edx, OFFSET msgLoad
    call WriteString
    mov edx, argFile
    call WriteString
    mov edx, OFFSET msgParen
    call WriteString
    mov eax, fileSize
    call WriteDec
    mov edx, OFFSET msgBytes
    call WriteString
    call Crlf
    mov edx, OFFSET msgKeyRun
    call WriteString
    call Crlf
    mov eax, fileSize               ; PKCS#7 always adds a block
    shr eax, 3
    inc eax
    mov edx, OFFSET msgProc
    call WriteString
    call WriteDec
    mov edx, OFFSET msgBlocks
    call WriteString
    call Crlf

    mov outSize, 0
    ; TODO (Module B+C): encrypt fileBuffer[fileSize] -> outBuffer with PKCS#7 padding
    ;   push OFFSET keyBytes / push OFFSET outBuffer / push fileSize / push OFFSET fileBuffer
    ;   call DesEncryptEcb   ; EAX = output size
    ;   mov outSize, eax
    mov suffixPtr, OFFSET sufEnc
    mov doneMsgPtr, OFFSET msgEncDone
    jmp FinishSave

DoDecrypt:
    push OFFSET keyBytes
    push DWORD PTR [tokPtrs+8]
    call ParseHexKey
    test eax, eax
    jz BadKey

    mov eax, [tokPtrs+4]
    mov argFile, eax
    push MAX_FILE
    push OFFSET fileBuffer
    push argFile
    call LoadFile
    cmp eax, -1
    je BadFile
    mov fileSize, eax
    test fileSize, 7                ; must be a multiple of 8
    jnz BadCipherLen

    mov edx, OFFSET msgLoad
    call WriteString
    mov edx, argFile
    call WriteString
    mov edx, OFFSET msgParen
    call WriteString
    mov eax, fileSize
    call WriteDec
    mov edx, OFFSET msgBytes
    call WriteString
    call Crlf
    mov edx, OFFSET msgKeyRun
    call WriteString
    call Crlf
    mov eax, fileSize
    shr eax, 3
    mov edx, OFFSET msgProc
    call WriteString
    call WriteDec
    mov edx, OFFSET msgBlocks
    call WriteString
    call Crlf

    mov outSize, 0
    ; TODO (Module B+C): decrypt + remove PKCS#7 padding -> outBuffer, EAX = plaintext size
    ;   call DesDecryptEcb / mov outSize, eax
    mov suffixPtr, OFFSET sufDec
    mov doneMsgPtr, OFFSET msgDecDone
    jmp FinishSave

DoDump:
    push MAX_FILE
    push OFFSET fileBuffer
    push DWORD PTR [tokPtrs+4]
    call LoadFile
    cmp eax, -1
    je BadFile
    mov fileSize, eax
    ; TODO (Module D): push fileSize / push OFFSET fileBuffer / call DisplayHexDump
    jmp ShellLoop

DoStats:
    push MAX_FILE
    push OFFSET fileBuffer
    push DWORD PTR [tokPtrs+4]
    call LoadFile
    cmp eax, -1
    je BadFile
    mov fileSize, eax
    ; TODO (Module D): call ComputeBufferStats and print top occurrences
    jmp ShellLoop

DoClear:
    call Clrscr
    jmp ShellLoop

; shared tail of ENCRYPT / DECRYPT: build output name, write file, report
FinishSave:
    cmp outSize, 0
    je NotReady
    push suffixPtr
    push argFile
    push OFFSET outName
    call BuildOutName               ; outName = file + suffix
    push outSize
    push OFFSET outBuffer
    push OFFSET outName
    call SaveFile
    cmp eax, -1
    je BadSave
    mov edx, doneMsgPtr
    call WriteString
    mov al, '"'
    call WriteChar
    mov edx, OFFSET outName
    call WriteString
    mov al, '"'
    call WriteChar
    call Crlf
    jmp ShellLoop

ExitShell:
    mov edx, OFFSET msgBye
    call WriteString
    call Crlf
    xor eax, eax                    ; return value to main.asm
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
RunShell ENDP


; =========================================================
; Procedure: ParseCommandLine(pBuffer)      [stdcall, ret 4]
;   FSM tokenizer. Splits the line IN PLACE (writes 0 at token ends)
;   and stores token pointers in tokPtrs[0..2].
;   Supports "quoted file names" with spaces.
;   Returns EAX = number of tokens (0..3)
;           -1 = missing closing quote
;           -2 = more than 3 tokens
;           -3 = misplaced quote (inside a word / quoted command)
; =========================================================
ParseCommandLine PROC
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov esi, [ebp+8]
    xor ebx, ebx                    ; BL = state (S_GAP)
    xor edi, edi                    ; EDI = token count
    mov DWORD PTR [tokPtrs], 0
    mov DWORD PTR [tokPtrs+4], 0
    mov DWORD PTR [tokPtrs+8], 0

PL_Next:
    mov al, [esi]
    cmp bl, S_GAP
    je PL_Gap
    cmp bl, S_QARG
    je PL_Quoted

; ---- state S_WORD ----
    cmp al, 0
    je PL_Done
    cmp al, ' '
    je PL_EndTok
    cmp al, 9
    je PL_EndTok
    cmp al, '"'
    je PL_ErrMisplace
    inc esi
    jmp PL_Next

; ---- state S_QARG ----
PL_Quoted:
    cmp al, 0
    je PL_ErrQuote
    cmp al, '"'
    je PL_EndTok
    inc esi
    jmp PL_Next

PL_EndTok:                          ; terminate token, go back to gap
    mov BYTE PTR [esi], 0
    inc esi
    mov bl, S_GAP
    jmp PL_Next

; ---- state S_GAP ----
PL_Gap:
    cmp al, 0
    je PL_Done
    cmp al, ' '
    je PL_Skip
    cmp al, 9
    jne PL_Start
PL_Skip:
    inc esi
    jmp PL_Next

PL_Start:                           ; first char of a new token
    cmp edi, 3
    jae PL_ErrTooMany
    cmp al, '"'
    je PL_StartQuote
    mov [tokPtrs + edi*4], esi
    inc edi
    mov bl, S_WORD
    inc esi
    jmp PL_Next

PL_StartQuote:
    test edi, edi
    jz PL_ErrMisplace               ; the command itself cannot be quoted
    inc esi                         ; token starts after the quote
    mov [tokPtrs + edi*4], esi
    inc edi
    mov bl, S_QARG
    jmp PL_Next

PL_Done:
    mov eax, edi
    jmp PL_Exit
PL_ErrQuote:
    mov eax, -1
    jmp PL_Exit
PL_ErrTooMany:
    mov eax, -2
    jmp PL_Exit
PL_ErrMisplace:
    mov eax, -3
PL_Exit:
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret 4
ParseCommandLine ENDP


; =========================================================
; Procedure: ToUpperCase(pString)           [stdcall, ret 4]
; =========================================================
ToUpperCase PROC
    push ebp
    mov ebp, esp
    push eax
    push esi

    mov esi, [ebp+8]
UC_Loop:
    mov al, [esi]
    cmp al, 0
    je UC_Done
    cmp al, 'a'
    jb UC_Next
    cmp al, 'z'
    ja UC_Next
    and al, 11011111b
    mov [esi], al
UC_Next:
    inc esi
    jmp UC_Loop
UC_Done:
    pop esi
    pop eax
    pop ebp
    ret 4
ToUpperCase ENDP


; =========================================================
; Procedure: ParseHexKey(pString, pOut8)    [stdcall, ret 8]
;   Accepts optional 0x/0X prefix + exactly 16 hex digits.
;   Writes 8 bytes (big-endian order) to pOut8.
;   Returns EAX = 1 valid, 0 invalid
; =========================================================
ParseHexKey PROC
    push ebp
    mov ebp, esp
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov esi, [ebp+8]
    mov edi, [ebp+12]

    cmp BYTE PTR [esi], '0'
    jne PK_NoPrefix
    mov al, [esi+1]
    cmp al, 'x'
    je PK_Skip
    cmp al, 'X'
    jne PK_NoPrefix
PK_Skip:
    add esi, 2
PK_NoPrefix:
    mov ecx, 16                     ; 16 hex digits
    xor edx, edx                    ; EDX = digit index
PK_Loop:
    movzx eax, BYTE PTR [esi]
    cmp al, '0'
    jb PK_Bad
    cmp al, '9'
    jbe PK_Digit
    cmp al, 'A'
    jb PK_Bad
    cmp al, 'F'
    jbe PK_Upper
    cmp al, 'a'
    jb PK_Bad
    cmp al, 'f'
    ja PK_Bad
    sub al, 'a' - 10
    jmp PK_Have
PK_Upper:
    sub al, 'A' - 10
    jmp PK_Have
PK_Digit:
    sub al, '0'
PK_Have:
    test dl, 1
    jnz PK_Low
    shl al, 4                       ; even digit = high nibble
    mov bl, al
    jmp PK_Next
PK_Low:
    or bl, al                       ; odd digit = low nibble -> store byte
    mov eax, edx
    shr eax, 1
    mov [edi + eax], bl
PK_Next:
    inc esi
    inc edx
    dec ecx
    jnz PK_Loop

    cmp BYTE PTR [esi], 0           ; nothing may follow the 16 digits
    jne PK_Bad
    mov eax, 1
    jmp PK_Exit
PK_Bad:
    xor eax, eax
PK_Exit:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop ebp
    ret 8
ParseHexKey ENDP


; =========================================================
; Procedure: LoadFile(pName, pBuffer, maxBytes)   [stdcall, ret 12]
;   Returns EAX = bytes read, or -1 on error
; =========================================================
LoadFile PROC
    push ebp
    mov ebp, esp
    push ebx
    push ecx
    push edx

    mov edx, [ebp+8]
    call OpenInputFile
    cmp eax, INVALID_HANDLE_VALUE
    je LF_Fail
    mov ebx, eax                    ; EBX = handle
    mov edx, [ebp+12]
    mov ecx, [ebp+16]
    call ReadFromFile               ; EAX = bytes read, CF = error
    jc LF_ErrClose
    push eax
    mov eax, ebx
    call CloseFile
    pop eax
    jmp LF_Exit
LF_ErrClose:
    mov eax, ebx
    call CloseFile
LF_Fail:
    mov eax, -1
LF_Exit:
    pop edx
    pop ecx
    pop ebx
    pop ebp
    ret 12
LoadFile ENDP


; =========================================================
; Procedure: SaveFile(pName, pBuffer, count)      [stdcall, ret 12]
;   Returns EAX = bytes written, or -1 on error
; =========================================================
SaveFile PROC
    push ebp
    mov ebp, esp
    push ebx
    push ecx
    push edx

    mov edx, [ebp+8]
    call CreateOutputFile
    cmp eax, INVALID_HANDLE_VALUE
    je SF_Fail
    mov ebx, eax
    mov edx, [ebp+12]
    mov ecx, [ebp+16]
    call WriteToFile                ; EAX = bytes written
    push eax
    mov eax, ebx
    call CloseFile
    pop eax
    jmp SF_Exit
SF_Fail:
    mov eax, -1
SF_Exit:
    pop edx
    pop ecx
    pop ebx
    pop ebp
    ret 12
SaveFile ENDP


; =========================================================
; Procedure: BuildOutName(pDest, pSrc, pSuffix)   [stdcall, ret 12]
;   pDest = pSrc + pSuffix   (e.g. "secret.txt" + ".enc")
; =========================================================
BuildOutName PROC
    push ebp
    mov ebp, esp
    push eax
    push esi
    push edi

    mov edi, [ebp+8]
    mov esi, [ebp+12]
BN_Copy1:
    mov al, [esi]
    mov [edi], al
    inc esi
    inc edi
    test al, al
    jnz BN_Copy1
    dec edi                         ; back onto the terminating 0
    mov esi, [ebp+16]
BN_Copy2:
    mov al, [esi]
    mov [edi], al
    inc esi
    inc edi
    test al, al
    jnz BN_Copy2

    pop edi
    pop esi
    pop eax
    pop ebp
    ret 12
BuildOutName ENDP

END