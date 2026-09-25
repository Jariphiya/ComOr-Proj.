INCLUDE C:\Irvine\Irvine32.inc

.data
    headerStr   BYTE "[Address]  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F | ASCII", 0
    separator   BYTE " | ", 0
    spaceChar   BYTE " ", 0
    dotChar     BYTE ".", 0

.code

DisplayHexDump PROC
    push ebp
    mov ebp, esp
    pushad

    mov edx, OFFSET headerStr
    call WriteString
    call Crlf

    mov esi, [ebp+8]
    mov ecx, [ebp+12]
    mov ebx, 0

Dump_MainLoop:
    cmp ecx, 0
    je Dump_End

    mov eax, ebx
    call WriteHex
    mov edx, OFFSET spaceChar
    call WriteString
    call WriteString

    mov edi, 16
    cmp ecx, 16
    jae Dump_SetRowLength
    mov edi, ecx

Dump_SetRowLength:
    push esi
    push edi

Dump_HexLoop:
    cmp edi, 0
    je Dump_HexPadding
    mov al, byte ptr [esi]
    call WriteHexB
    mov edx, OFFSET spaceChar
    call WriteString
    inc esi
    dec edi
    jmp Dump_HexLoop

Dump_HexPadding:
    pop edi
    push edi
    mov eax, 16
    sub eax, edi
    cmp eax, 0
    je Dump_PrintSeparator
Dump_PadLoop:
    mov edx, OFFSET spaceChar
    call WriteString
    call WriteString
    call WriteString
    dec eax
    cmp eax, 0
    jne Dump_PadLoop

Dump_PrintSeparator:
    mov edx, OFFSET separator
    call WriteString

    pop edi
    pop esi
Dump_AsciiLoop:
    cmp edi, 0
    je Dump_NextLine
    mov al, byte ptr [esi]
    
    cmp al, 20h
    jb Dump_PrintDot
    cmp al, 7Eh
    ja Dump_PrintDot
    
    call WriteChar
    jmp Dump_AsciiNext

Dump_PrintDot:
    mov al, '.'
    call WriteChar

Dump_AsciiNext:
    inc esi
    dec edi
    jmp Dump_AsciiLoop

Dump_NextLine:
    call Crlf

    mov eax, 16
    cmp ecx, 16
    jb Dump_SubtractRest
    sub ecx, 16
    add ebx, 16
    jmp Dump_MainLoop

Dump_SubtractRest:
    sub ecx, ecx
    jmp Dump_MainLoop

Dump_End:
    popad
    pop ebp
    ret 8
DisplayHexDump ENDP

ComputeBufferStats PROC
    push ebp
    mov ebp, esp
    pushad

    mov edi, [ebp+12]

    mov ecx, 256
    mov ebx, 0
Stats_ClearLoop:
    mov dword ptr [edi + ebx*4], 0
    inc ebx
    cmp ebx, ecx
    jb Stats_ClearLoop

    mov esi, [ebp+8]
    mov ecx, [ebp+16]
    cmp ecx, 0
    je Stats_End

Stats_CountLoop:
    movzx eax, byte ptr [esi]
    inc dword ptr [edi + eax*4]
    
    inc esi
    dec ecx
    cmp ecx, 0
    jne Stats_CountLoop

Stats_End:
    popad
    pop ebp
    mov eax, 1
    ret 12
ComputeBufferStats ENDP

END