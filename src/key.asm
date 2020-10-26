.code

generate_key proc
mov     rdx, rcx
mov     rax, 22AAAA8A20000h
shr     rdx, 0Ch
mov     r8, 555555555h
and     rdx, rax
mov     rax, rcx
shl     rax, 11h
xor     rdx, rax
mov     rax, 71D67FFFEDA60000h
and     rdx, rax
mov     rax, rcx
shr     rax, 1Dh
and     rax, r8
xor     rdx, rax
xor     rdx, rcx
mov     rax, rdx
mov     rcx, rdx
and     eax, 7FFBF40h
shr     rcx, 25h
xor     rax, rcx
mov     rcx, rdx
shr     rax, 6
and     rcx, 0FFFFFFFFFFFFBF77h
shl     rcx, 25h
xor     rax, rcx
xor     rax, rdx
ret
generate_key endp

end