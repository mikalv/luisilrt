global EntryPoint

section .text vstart=0x00001000

EntryPoint:
call InitializeHandles
mov eax, [fs:0x0030]
mov eax, [eax+0x0008]
push eax
call LoadMSILExecutable
ret
align 16

; Error codes
%define ERROR_SUCCESS 0
%define ERROR_BAD_FORMAT 11

; Imports from ntdll.dll
ntdll_RtlEnterCriticalSection dd 0x77A822C0
ntdll_RtlLeaveCriticalSection dd 0x77A82280
ntdll_RtlAllocateHeap dd 0x77A8E046
ntdll_ZwTerminateProcess dd 0x77A7FCB0
ntdll_ZwAllocateVirtualMemory dd 0x77A7FAC0

; Imports from kernel32.dll
kernel32_LoadLibraryW dd 0x758448F3
kernel32_WriteConsoleW dd 0x75867A92
kernel32_GetStdHandle dd 0x7584517B

; Import call points
RtlEnterCriticalSection:
call GetModuleBase
jmp dword [eax-0x7D5A0000+ntdll_RtlEnterCriticalSection]

RtlLeaveCriticalSection:
call GetModuleBase
jmp dword [eax-0x7D5A0000+ntdll_RtlLeaveCriticalSection]

RtlAllocateHeap:
call GetModuleBase
jmp dword [eax-0x7D5A0000+ntdll_RtlAllocateHeap]

ZwTerminateProcess:
call GetModuleBase
jmp dword [eax-0x7D5A0000+ntdll_ZwTerminateProcess]

ZwAllocateVirtualMemory:
call GetModuleBase
jmp dword [eax-0x7D5A0000+ntdll_ZwAllocateVirtualMemory]

LoadLibraryW:
call GetModuleBase
jmp dword [eax-0x7D5A0000+kernel32_LoadLibraryW]

WriteConsoleW:
call GetModuleBase
jmp dword [eax-0x7D5A0000+kernel32_WriteConsoleW]

GetStdHandle:
call GetModuleBase
jmp dword [eax-0x7D5A0000+kernel32_GetStdHandle]

GetModuleBase:
mov eax, [esp]
xor ax, ax
ret

InitializeHandles:
push -10
call GetStdHandle
mov ecx, eax
call GetModuleBase
mov [eax-0x7D5A0000+stdin], ecx
push -11
call GetStdHandle
mov ecx, eax
call GetModuleBase
mov [eax-0x7D5A0000+stdout], ecx
push -12
call GetStdHandle
mov ecx, eax
call GetModuleBase
mov [eax-0x7D5A0000+stderr], ecx
ret

ValidatePEHeader:
push ebp
mov ebp, esp
mov ecx, [ebp+0x08]
xor eax, eax
cmp word [ecx], 0x5A4D
jnz .error
mov eax, [ecx+0x3C]
cmp dword [eax+ecx], 0x00004550
jnz .error
add eax, ecx
push byte +0
call SetLastError
.return:
pop ebp
ret 0x0004
.error:
push byte +11
call SetLastError
jmp short .return

strlenW:
mov ecx, [esp+0x04]
xor eax, eax
.loop:
cmp word [eax*2+ecx], byte +0
jz .end
add eax, byte +1
jmp short .loop
.end:
ret 0x0004

WriteText:
push ebp
mov ebp, esp
push byte +1
push dword [ebp+0x0C]
push dword [ebp+0x08]
call strlenW
push eax
push dword [ebp+0x08]
call GetModuleBase
cmp dword [ebp+0x10], byte +0
jnz .stdout
push dword [eax-0x7D5A0000+stderr]
jmp short .write
.stdout:
push dword [eax-0x7D5A0000+stdout]
.write:
call WriteConsoleW
pop ebp
ret 0x000C

LocateDirectory:
push ebp
mov ebp, esp
mov eax, [ebp+0x08]
mov ecx, [ebp+0x0C]
mov edx, [eax+ecx*8+0x78]
cmp edx, byte +0
jz .not_found
cmp dword [eax+ecx*8+0x7C], byte +0
jz .not_found
mov eax, edx
.return:
pop ebp
ret 0x0008
.not_found:
xor eax, eax
jmp short .return

SearchStream:
push ebp
mov ebp, esp

pop ebp
ret 0x000C

GetManagedStringLength:
push ebp
mov ebp, esp
mov eax, [ebp+0x08]
add eax, 2
push eax
call strlenW
pop ebp
ret 0x0004

GetLastError:
mov eax, [fs:0x0034]
ret

SetLastError:
mov eax, [esp+0x04]
mov [fs:0x0034], eax
ret 0x0004

ManagedUnwind:
push ebp
mov ebp, esp
pop ebp
ret 0x0004

AddSEHChainLink:
mov ecx, [esp+0x08]
mov edx, [fs:0x0000]
mov [ecx], edx
mov edx, [esp+0x04]
mov [ecx+0x04], edx
mov [fs:0x0000], ecx
ret

RemoveSEHChainLink:
mov ecx, [fs:0x0000]
mov ecx, [ecx]
mov [fs:0x0000], ecx
ret

LoadMSILExecutable:
push ebp
mov ebp, esp
sub esp, byte +0x30
lea ecx, [ebp-0x2C]
push ecx
push dword ManagedUnwind
call AddSEHChainLink
push dword [ebp+0x08]
call ValidatePEHeader
test eax, eax
jz near .pe_error
push 14
push eax
call LocateDirectory
test eax, eax
jz near .clr_error
add eax, [ebp+0x08]
mov [ebp-0x04], eax
mov ecx, [eax+0x08]
add ecx, [ebp+0x08]
mov [ebp-0x08], ecx
mov ecx, [eax+0x14]
mov [ebp-0x0C], ecx
mov eax, [ebp-0x08]
add eax, [eax+0x0C]
add eax, byte +0x14
mov [ebp-0x14], eax
movzx ecx, word [eax-0x02]
push ecx
push eax
call GetModuleBase
add eax, first_stream_id-0x7D5A0000
push eax
call SearchStream
mov [ebp-0x18], eax
mov eax, [ebp-0x14]
movzx ecx, word [eax-0x02]
push ecx
push eax
call GetModuleBase
add eax, strings_stream_id-0x7D5A0000
push eax
call SearchStream
mov [ebp-0x1C], eax
mov eax, [ebp-0x14]
movzx ecx, word [eax-0x02]
push ecx
push eax
call GetModuleBase
add eax, guids_stream_id-0x7D5A0000
push eax
call SearchStream
mov [ebp-0x20], eax
mov eax, [ebp-0x14]
movzx ecx, word [eax-0x02]
push ecx
push eax
call GetModuleBase
add eax, blob_stream_id-0x7D5A0000
push eax
call SearchStream
mov [ebp-0x24], eax
push byte +64
push byte +0
mov eax, [fs:0x0030]
push dword [eax+0x0018]
call RtlAllocateHeap
mov [ebp-0x30], eax
push dword user32_string
call LoadLibraryW
jmp short .return

.pe_error:
push byte +1
lea eax, [ebp-0x10]
push eax
call GetModuleBase
lea edx, [eax+pe_error-0x7D5A0000]
push edx
call WriteText
jmp short .return

.clr_error:
push byte +1
lea eax, [ebp-0x10]
push eax
call GetModuleBase
lea edx, [eax+clr_error-0x7D5A0000]
push edx
call WriteText

.return:
call RemoveSEHChainLink
call GetLastError
test eax, eax
jz .success
add eax, 0x80070000
.success:
mov esp, ebp
pop ebp
ret 0x0004
times 0x0000F000-($-$$) db 0

first_stream_id db "#~", 0
strings_stream_id db "#Strings", 0
guids_stream_id db "#GUID", 0
blob_stream_id db "#Blob", 0
user32_string db "u", 0, "s", 0, "e", 0, "r", 0, "3", 0, "2", 0, ".", 0, "d", 0, "l", 0, "l", 0, 0, 0
pe_error db "P", 0, "E", 0, " ", 0, "h", 0, "e", 0, "a", 0, "d", 0, "e", 0, "r", 0, " ", 0, "i", 0, "s", 0, " ", 0, "i", 0, "n", 0, "v", 0, "a", 0, "l", 0, "i", 0, "d", 0, 0, 0
clr_error db "C", 0, "L", 0, "R", 0, " ", 0, "e", 0, "r", 0, "r", 0, "o", 0, "r", 0, 13, 0, 10, 0, 0, 0

section .data
stdin dd 0
stdout dd 0
stderr dd 0

section .edata

%define RVA(x) (x - 0x7D5A0000)

dd 0
dd 1417161600
dw 7
dw 1
dd RVA(luisilrt_string)
dd 0
dd 16
dd 16
dd RVA(luisilrt_functions)
dd RVA(luisilrt_names)
dd RVA(luisilrt_ordinals)

luisilrt_string db "luisilrt.dll", 0

luisilrt_functions:
dd RVA(EntryPoint)
dd RVA(ValidatePEHeader)
dd RVA(LocateDirectory)
dd RVA(SearchStream)
dd RVA(LoadMSILExecutable)
dd RVA(GetManagedStringLength)
dd RVA(RtlEnterCriticalSection)
dd RVA(RtlLeaveCriticalSection)
dd RVA(RtlAllocateHeap)
dd RVA(ZwTerminateProcess)
dd RVA(ZwAllocateVirtualMemory)
dd RVA(LoadLibraryW)
dd RVA(WriteConsoleW)
dd RVA(GetStdHandle)
dd RVA(GetLastError)
dd RVA(SetLastError)
dd 0

luisilrt_names:
dd RVA(name1)
dd RVA(name2)
dd RVA(name3)
dd RVA(name4)
dd RVA(name5)
dd RVA(name6)
dd RVA(name7)
dd RVA(name8)
dd RVA(name9)
dd RVA(name10)
dd RVA(name11)
dd RVA(name12)
dd RVA(name13)
dd RVA(name14)
dd RVA(name15)
dd RVA(name16)
dd 0

luisilrt_ordinals:
dw 0
dw 1
dw 2
dw 3
dw 4
dw 5
dw 6
dw 7
dw 8
dw 9
dw 10
dw 11
dw 12
dw 13
dw 14
dw 15
dw -1

name1 db "EntryPoint", 0
name2 db "ValidatePEHeader", 0
name3 db "LocateDirectory", 0
name4 db "SearchStream", 0
name5 db "LoadMSILExecutable", 0
name6 db "GetManagedStringLength", 0
name7 db "RtlEnterCriticalSection", 0
name8 db "RtlLeaveCriticalSection", 0
name9 db "RtlAllocateHeap", 0
name10 db "ZwTerminateProcess", 0
name11 db "ZwAllocateVirtualMemory", 0
name12 db "LoadLibraryW", 0
name13 db "WriteConsoleW", 0
name14 db "GetStdHandle", 0
name15 db "GetLastError", 0
name16 db "SetLastError", 0
