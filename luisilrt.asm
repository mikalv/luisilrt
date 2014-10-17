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

; Import call points
RtlInitializeCriticalSection:
call GetModuleBase
jmp dword [eax-0x7D5A0000+ntdll_RtlInitializeCriticalSection]

RtlDeleteCriticalSection:
call GetModuleBase
jmp dword [eax-0x7D5A0000+ntdll_RtlDeleteCriticalSection]

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
push byte -10
call GetStdHandle
mov ecx, eax
call GetModuleBase
mov [eax-0x7D5A0000+stdin], ecx
push byte -11
call GetStdHandle
mov ecx, eax
call GetModuleBase
mov [eax-0x7D5A0000+stdout], ecx
push byte -12
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
push eax
push byte +0
call SetLastError
pop eax
add eax, ecx
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
cmp dword [ebp+0x08], byte +0
jnz .search_level1
.argument_exception:
call RaiseArgumentException
xor eax, eax
jmp short .return
.search_level1:
cmp dword [ebp+0x10], byte +0
jle .argument_exception
push esi
push edi
mov esi, [ebp+0x08]
mov edi, [ebp+0x0C]
add edi, byte +8
mov eax, [ebp+0x10]
.loop:
push eax
mov edx, edi
or ecx, byte -1
xor eax, eax
repne scasb
not ecx
mov edi, edx
mov esi, [ebp+0x08]
repe cmpsb
je .found
and edi, byte -4
add edi, byte +4
pop eax
sub eax, byte +1
jnz .loop
xor eax, eax
jmp short .return
.found:
add esp, byte +4
mov eax, edi
sub eax, byte +8
.return:
pop edi
pop esi
pop ebp
ret 0x000C

RaiseArgumentException:
push 0x80070057
call SetLastError
mov ecx, [esp]
call GetModuleBase
mov [eax-0x7D5A0000+argument_exception_record+0x0C], ecx
add eax, argument_exception_record-0x7D5A0000
push eax
call ManagedUnwind
pop ebp
ret

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

ProcessILOpcode:
push ebp
mov ebp, esp
call GetModuleBase
mov edx, [eax-0x7D5A0000+cil_position]
movzx edx, word [edx]
inc dword [eax-0x7D5A0000+cil_position]
mov edx, [eax+edx*4-0x7D5A0000+cil_opcode_table]
lea edx, [edx+eax-0x7D5A0000]
jmp edx

.return:
ProcessNop:
pop ebp
ret

ProcessBreak:
int3
jmp short ProcessILOpcode.return

ProcessLdarg0:
push byte +0
call LoadArgument
jmp short ProcessILOpcode.return

ProcessLdarg1:
push byte +1
call LoadArgument
jmp short ProcessILOpcode.return

ProcessLdarg2:
push byte +2
call LoadArgument
jmp short ProcessILOpcode.return

ProcessLdarg3:
push byte +3
call LoadArgument
jmp short ProcessILOpcode.return

ProcessLdloc0:
push byte +0
call LoadLocal
jmp short ProcessILOpcode.return

ProcessLdloc1:
push byte +1
call LoadLocal
jmp short ProcessILOpcode.return

ProcessLdloc2:
push byte +2
call LoadLocal
jmp short ProcessILOpcode.return

ProcessLdloc3:
push byte +3
call LoadLocal
jmp short ProcessILOpcode.return

ProcessStloc0:
push byte +0
call StoreLocal
jmp ProcessILOpcode.return

ProcessStloc1:
push byte +1
call StoreLocal
jmp ProcessILOpcode.return

ProcessStloc2:
push byte +2
call StoreLocal
jmp ProcessILOpcode.return

ProcessStloc3:
push byte +3
call StoreLocal
jmp ProcessILOpcode.return

ProcessLdargS:
call GetModuleBase
mov edx, [eax-0x7D5A0000+cil_position]
movzx ecx, byte [edx]
push ecx
inc dword [eax-0x7D5A0000+cil_position]
call LoadArgument
jmp ProcessILOpcode.return

ProcessLdlocS:
call GetModuleBase
mov edx, [eax-0x7D5A0000+cil_position]
movzx ecx, byte [edx]
push ecx
inc dword [eax-0x7D5A0000+cil_position]
call LoadArgument
jmp ProcessILOpcode.return

LoadArgument:
push ebp
mov ebp, esp
call GetModuleBase
mov edx, [eax-0x7D5A0000+cil_callstack]
mov ecx, [edx+0x08]
add ecx, 0x0400
mov eax, [ebp+0x08]
shl eax, 3
add ecx, eax
mov eax, [ecx]
test dword [ecx+0x04], 64
jnz .reference
cmp dword [ecx+0x04], byte +1
jz .return
cmp dword [ecx+0x08], byte +18
jz .return
mov eax, [eax]
jmp short .return
.reference:
mov eax, [eax]
mov eax, [eax]
.return:

pop ebp
ret

LoadLocal:
push ebp
mov ebp, esp
call GetModuleBase
mov edx, [eax-0x7D5A0000+cil_callstack]
mov ecx, [edx+0x04]
add ecx, 0x0400
mov eax, [ebp+0x08]
shl eax, 2
add ecx, eax
mov eax, [ecx]
test dword [ecx+0x04], 64
jnz .reference
cmp dword [ecx+0x04], byte +1
jz .return
cmp dword [ecx+0x08], byte +18
jz .return
mov eax, [eax]
jmp short .return
.reference:
mov eax, [eax]
mov eax, [eax]
.return:
pop ebp
ret 0x0004

StoreLocal:
push ebp
mov ebp, esp
call GetModuleBase
mov edx, [eax-0x7D5A0000+cil_callstack]
mov ecx, [edx+0x04]
add ecx, 0x0400
mov eax, [ebp+0x08]
shl eax, 2
add ecx, eax
mov eax, [ebp+0x0C]
test dword [ecx+0x04], 64
jnz .reference
cmp dword [ecx+0x04], byte +1
jz .return
cmp dword [ecx+0x08], byte +18
jz .return
mov [ecx], eax
jmp short .return
.reference:
mov ecx, [ecx]
mov [ecx], eax
.return:
pop ebp
ret 0x0008

ManagedUnwind:
push ebp
mov ebp, esp
or eax, byte -1
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
push byte +14
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
push dword 4096
push byte +0
mov eax, [fs:0x0030]
push dword [eax+0x0018]
call RtlAllocateHeap
add eax, 0x0FF0
mov [cil_callstack], eax
mov ecx, [ebp-0x0C]
mov [eax], ecx
push eax
push dword 0x0600
push byte +0
mov eax, [fs:0x0030]
push dword [eax+0x0018]
call RtlAllocateHeap
mov edx, eax
pop eax
mov [eax+0x04], edx
push eax
push byte +64
push byte +0
mov eax, [fs:0x0030]
push dword [eax+0x0018]
call RtlAllocateHeap
mov edx, eax
pop eax
mov [eax+0x08], edx
push eax
push dword 0x0008
push byte +0
mov eax, [fs:0x0030]
push dword [eax+0x0018]
call RtlAllocateHeap
mov edx, eax
pop eax
mov [eax+0x0C], edx
or dword [edx], byte -1
mov dword [edx+4], .return
push dword stack_init_string
call WriteText
mov eax, [ebp-0x0C]
and eax, 0xFF000000
cmp eax, 0x06000000
jnz near .clr_error
push dword [ebp-0x0C]
call NumberToString
push dword input
push eax
call wstrcpy
push dword entry_method_loaded
call WriteText
.cil_loop:
call ProcessILOpcode
call GetLastError
test eax, eax
jnz .cil_loop
call ManagedUnwind
test eax, eax
jns .cil_loop
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

RtlEnterCriticalSection:
push ebp
mov ebp, esp
sub esp, byte +0x0C
xor eax, eax
mov esp, ebp
pop ebp
ret 0x0004
RtlLeaveCriticalSection:
mov edi, edi
push ebp
mov ebp, esp
push esi
mov esi, [ebp+0x08]
add dword [esi+0x08], byte +1
jnz .skip
push ebx
push edi
lea edi, [esi+0x04]
and dword [esi+0x0C], byte +0
mov ebx, 1
mov eax, edi
lock xadd [eax], ebx
inc ebx
cmp ebx, -1
jnz .other
.restore:
pop edi
pop ebx
.skip:
xor eax, eax
pop esi
pop ebp
ret 0x0004
.other:
jmp short .skip

AnsiToUnicode:
push ebp
mov ebp, esp
push edi
mov edi, [ebp+0x08]
or ecx, byte -1
mov al, 0
repne scasb
not ecx
shl ecx, byte +1
push ecx
push ecx
push byte +0
mov eax, [fs:0x0030]
push dword [eax+0x0018]
call RtlAllocateHeap
pop ecx
push esi
mov esi, edi
shr ecx, byte +1
sub esi, ecx
sub esi, byte +1
mov edi, eax
mov al, 0
jecxz .skip
.loop:
movsb
stosb
loop .loop
.skip:
pop esi
pop edi
pop ebp
ret 0x0004

NumberToString:
push ebp
mov ebp, esp
sub esp, byte +0x04
push byte +20
push byte +0
mov eax, [fs:0x0030]
push dword [eax+0x0018]
call RtlAllocateHeap
mov [ebp-0x04], eax
mov [ebp-0x08], eax
mov eax, [ebp+0x08]
.loop1:
mov ecx, 10
xor edx, edx
div ecx
add dl, 0x30
mov ecx, [ebp-0x04]
mov [ecx], dl
mov byte [ecx+1], 0
add dword [ebp-0x04], byte +2
test eax, eax
jnz .loop1
mov eax, [ebp-0x08]
mov edx, [ebp-0x04]
sub edx, byte +1
.loop2:
mov cl, [eax]
mov ch, [edx]
mov [eax], ch
mov [edx], cl
add eax, 1
sub edx, 1
cmp eax, edx
jl .loop2
mov eax, [ebp-0x08]
xor ecx, ecx
lea edx, [eax+20]
.loop3:
mov cx, [eax]
xchg cl, ch
mov [eax], cx
add eax, byte +2
cmp eax, edx
jnz .loop3
mov eax, [ebp-0x08]
mov esp, ebp
pop ebp
ret

wstrcpy:
push ebp
mov ebp, esp
sub esp, byte 0x08
mov eax, [ebp+0x08]
mov [ebp-0x04], eax
mov eax, [ebp+0x0C]
mov [ebp-0x08], eax
.loop_process:
mov eax, [ebp-0x04]
mov edx, [ebp-0x08]
mov cx, [edx]
mov [eax], cx
add dword [ebp-0x04], byte 2
add dword [ebp-0x08], byte 2
.start_loop:
test cl, cl
jnz .loop_process
mov eax, [ebp-0x04]
mov byte [eax], 0
mov esp, ebp
pop ebp
ret 0x0008

_CorExeMain:
jmp EntryPoint

_CorValidateImage:
push dword [esp+0x04]
call ValidatePEHeader
test eax, eax
jnz .error
push 0x0E
push eax
call LocateDirectory
xor eax, eax
mov al, 1
jmp short .return
.error:
xor eax, eax
.return:
ret 0x0004

_CorDllMain:
jmp short _CorExeMain

_CorImageUnloading:
xor eax, eax
ret

first_stream_id db "#~", 0
strings_stream_id db "#Strings", 0
guids_stream_id db "#GUID", 0
blob_stream_id db "#Blob", 0
align 2
user32_string db "u", 0, "s", 0, "e", 0, "r", 0, "3", 0, "2", 0, ".", 0, "d", 0, "l", 0, "l", 0, 0, 0
pe_error db "P", 0, "E", 0, " ", 0, "h", 0, "e", 0, "a", 0, "d", 0, "e", 0, "r", 0, " ", 0, "i", 0, "s", 0, " ", 0, "i", 0, "n", 0, "v", 0, "a", 0, "l", 0, "i", 0, "d", 0, 0, 0
clr_error db "C", 0, "L", 0, "R", 0, " ", 0, "e", 0, "r", 0, "r", 0, "o", 0, "r", 0, 13, 0, 10, 0, 0, 0
stack_init_string db "T", 0, "h", 0, "e", 0, " ", 0, "c", 0, "a", 0, "l", 0, "l", 0, " ", 0, "s", 0, "t", 0, "a", 0, "c", 0, "k", 0, " ", 0, "w", 0, "a", 0, "s", 0, "i", 0, "n", 0, "i", 0, "t", 0, "i", 0, "a", 0, "l", 0, "i", 0, "z", 0, "e", 0, "d", 0, " ", 0, "s", 0, "u", 0, "c", 0, "c", 0, "e", 0, "s", 0, "f", 0, "u", 0, "l", 0, "l", 0, "y", 0, ".", 0, 13, 0, 10, 0, 0, 0
entry_method_loaded db "M", 0, "a", 0, "i", 0, "n", 0, " ", 0, "m", 0, "e", 0, "t", 0, "h", 0, "o", 0, "d", 0, "l", 0, "o", 0, "a", 0, "d", 0, "e", 0, "d", 0, " ", 0, "s", 0, "u", 0, "c", 0, "c", 0, "e", 0, "s", 0, "s", 0, "f", 0, "u", 0, "l", 0, "l", 0, "y", 0, " ", 0, "w", 0, "i", 0, "t", 0, "h", 0, " ", 0, "R", 0, "I", 0, "D", 0
input: times 10 dw 0x30

times 0x0000F000-($-$$) db 0
section .data
stdin dd 0
stdout dd 0
stderr dd 0
cil_position dd 0
cil_stack_position dd 0
cil_callstack dd 0
cil_callstack_pos dd 0

argument_exception_record:
dd -1
dd 0
dd -1
dd 0
dd 1
dd 0x80070057

cil_opcode_table:
dd ProcessNop
dd ProcessBreak
dd ProcessLdarg0
dd ProcessLdarg1
dd ProcessLdarg2
dd ProcessLdarg3
dd ProcessLdloc0
dd ProcessLdloc1
dd ProcessLdloc2
dd ProcessLdloc3
dd ProcessStloc0
dd ProcessStloc1
dd ProcessStloc2
dd ProcessStloc3
dd ProcessLdargS
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessLdlocS
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return
dd ProcessILOpcode.return

section .edata

%define RVA(x) (x - 0x7D5A0000)

dd 0
dd 1417161600
dw 7
dw 1
dd RVA(luisilrt_string)
dd 0
dd 18
dd 18
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
dd RVA(RtlInitializeCriticalSection)
dd RVA(RtlDeleteCriticalSection)
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
dd RVA(name17)
dd RVA(name18)
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
dw 16
dw 17
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
name17 db "RtlInitializeCriticalSection", 0
name18 db "RtlDeleteCriticalSection", 0

section .idata vstart=0x00013000
dd RVA(ntdll_LookupTable)
dd 1417161600
dd 0
dd RVA(ntdll_string)
dd RVA(ntdll_imports)
dd RVA(kernel32_LookupTable)
dd 1417161600
dd 0
dd RVA(kernel32_string)
dd RVA(kernel32_imports)
dd 0
dd 0
dd 0
dd 0
dd 0

ntdll_string:
db "ntdll.dll", 0, 0, 0

ntdll_LookupTable:
dd RVA(ntdll_Function1)
dd RVA(ntdll_Function2)
dd RVA(ntdll_Function3)
dd RVA(ntdll_Function4)
dd RVA(ntdll_Function5)
dd 0

ntdll_imports:
ntdll_RtlInitializeCriticalSection:
dd RVA(ntdll_Function1)
ntdll_RtlDeleteCriticalSection:
dd RVA(ntdll_Function2)
ntdll_RtlAllocateHeap:
dd RVA(ntdll_Function3)
ntdll_ZwTerminateProcess:
dd RVA(ntdll_Function4)
ntdll_ZwAllocateVirtualMemory:
dd RVA(ntdll_Function5)
dd 0

ntdll_Function1:
dw 1
dw "RtlInitializeCriticalSection", 0
ntdll_Function2:
dw 2
dw "RtlDeleteCriticalSection", 0
ntdll_Function3:
dw 3
dw "RtlAllocateHeap", 0
ntdll_Function4:
dw 4
dw "NtTerminateProcess", 0
ntdll_Function5:
dw 5
dw "NtAllocateVirtualMemory", 0
dw 0
dw 0
align 4

kernel32_string db "kernel32.dll", 0, 0, 0, 0

kernel32_LookupTable:
dd RVA(kernel32_Function1)
dd RVA(kernel32_Function2)
dd RVA(kernel32_Function3)
dd 0

kernel32_imports:
kernel32_LoadLibraryW:
dd RVA(kernel32_Function1)
kernel32_WriteConsoleW:
dd RVA(kernel32_Function2)
kernel32_GetStdHandle:
dd RVA(kernel32_Function3)
dd 0

kernel32_Function1:
dw 1
dw "LoadLibraryW", 0
kernel32_Function2:
dw 2
dw "WriteConsoleW", 0
kernel32_Function3:
dw 3
dw "GetStdHandle", 0
dw 0
dw 0
