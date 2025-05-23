section .text

; =============== S U B R O U T I N E =======================================
global ossl_sm4_set_key
; __int64 __fastcall ossl_sm4_set_key(const uint8_t *key, SM4_KEY *ks)
ossl_sm4_set_key:                       ; CODE XREF: sm4_init_key+5B↑p
                                        ; sub_5120D0+14↓p ...
; __unwind {
                push    rbp
                push    rbx
                mov     rbx, rsi
                xor     esi, esi        ; n
                call    load_u32_be
                mov     esi, 1          ; n
                xor     eax, 0A3B1BAC6h
                mov     r11d, eax
                call    load_u32_be
                mov     esi, 2          ; n
                xor     eax, 56AA3350h
                mov     r10d, eax
                call    load_u32_be
                mov     esi, 3          ; n
                xor     eax, 677D9197h
                mov     r9d, eax
                call    load_u32_be
                xor     esi, esi
                xor     eax, 0B27022DCh
                mov     r8d, eax

loc_4E030C:                             ; CODE XREF: ossl_sm4_set_key+C4↓j
                mov     edi, r10d
                xor     edi, r9d
                xor     edi, r8d
                xor     edi, CK[rsi]
                call    SM4_key_sub
                mov     edi, r9d
                xor     r11d, eax
                xor     edi, r8d
                xor     edi, r11d
                xor     edi, (CK+4)[rsi]
                call    SM4_key_sub
                mov     edi, (CK+8)[rsi]
                xor     r10d, eax
                mov     ebp, r11d
                xor     ebp, r10d
                xor     edi, r8d
                xor     edi, ebp
                call    SM4_key_sub
                mov     edi, (CK+0Ch)[rsi]
                xor     r9d, eax
                xor     edi, r9d
                xor     edi, ebp
                call    SM4_key_sub
                xor     r8d, eax
                mov     [rbx+rsi], r11d
                mov     [rbx+rsi+4], r10d
                mov     [rbx+rsi+8], r9d
                mov     [rbx+rsi+0Ch], r8d
                add     rsi, 10h
                cmp     rsi, 80h
                jnz     short loc_4E030C
                mov     eax, 1
                pop     rbx
                pop     rbp
                retn
; } // starts at 4E02C0

; =============== S U B R O U T I N E =======================================
global ossl_sm4_encrypt
; void __fastcall ossl_sm4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
ossl_sm4_encrypt:                       ; DATA XREF: sm4_init_key+35↑o
                                        ; sub_512359+39↓o ...
; __unwind {
                push    r12
                mov     r11, rsi
                xor     esi, esi        ; n
                mov     r10, rdx
                push    rbp
                push    rbx
                call    load_u32_be
                mov     esi, 1          ; n
                mov     r9d, eax
                call    load_u32_be
                mov     esi, 2          ; n
                mov     ebp, eax
                call    load_u32_be
                mov     esi, 3          ; n
                mov     ebx, eax
                call    load_u32_be
                mov     edi, ebp
                xor     edi, ebx
                xor     edi, [r10+7Ch]
                mov     r8d, eax
                xor     edi, eax
                call    SM4_T_slow
                mov     edi, ebx
                xor     r9d, eax
                xor     edi, r8d
                xor     edi, [r10+78h]
                xor     edi, r9d
                call    SM4_T_slow
                mov     edi, [r10+74h]
                xor     ebp, eax
                mov     esi, r9d
                xor     esi, ebp
                xor     edi, r8d
                xor     edi, esi
                call    SM4_T_slow
                mov     edi, [r10+70h]
                xor     ebx, eax
                xor     edi, ebx
                xor     edi, esi
                call    SM4_T_slow
                mov     edi, ebp
                xor     r8d, eax
                xor     edi, ebx
                xor     edi, [r10+6Ch]
                xor     edi, r8d
                call    SM4_T
                mov     edi, ebx
                xor     r9d, eax
                xor     edi, r8d
                xor     edi, [r10+68h]
                xor     edi, r9d
                call    SM4_T
                mov     edi, [r10+64h]
                xor     ebp, eax
                mov     r12d, r9d
                xor     r12d, ebp
                xor     edi, r8d
                xor     edi, r12d
                call    SM4_T
                mov     edi, [r10+60h]
                xor     ebx, eax
                mov     esi, ebx
                xor     edi, ebx
                xor     edi, r12d
                call    SM4_T
                mov     edi, ebp
                xor     r8d, eax
                xor     edi, ebx
                xor     edi, [r10+5Ch]
                xor     edi, r8d
                call    SM4_T
                mov     edi, ebx
                mov     ebx, ebp
                xor     r9d, eax
                xor     edi, r8d
                xor     edi, [r10+58h]
                xor     edi, r9d
                call    SM4_T
                mov     edi, [r10+54h]
                xor     ebx, eax
                mov     ebp, r9d
                xor     ebp, ebx
                xor     edi, r8d
                xor     edi, ebp
                call    SM4_T
                mov     edi, [r10+50h]
                xor     esi, eax
                xor     edi, esi
                xor     edi, ebp
                call    SM4_T
                mov     edi, ebx
                xor     r8d, eax
                xor     edi, esi
                xor     edi, [r10+4Ch]
                xor     edi, r8d
                call    SM4_T
                mov     edi, esi
                xor     r9d, eax
                xor     edi, r8d
                xor     edi, [r10+48h]
                xor     edi, r9d
                call    SM4_T
                mov     edi, [r10+44h]
                xor     ebx, eax
                mov     ebp, r9d
                xor     ebp, ebx
                xor     edi, r8d
                xor     edi, ebp
                call    SM4_T
                mov     edi, [r10+40h]
                xor     esi, eax
                xor     edi, esi
                xor     edi, ebp
                call    SM4_T
                mov     edi, ebx
                xor     r8d, eax
                xor     edi, esi
                xor     edi, [r10+3Ch]
                xor     edi, r8d
                call    SM4_T
                mov     edi, esi
                xor     r9d, eax
                xor     edi, r8d
                xor     edi, [r10+38h]
                xor     edi, r9d
                call    SM4_T
                mov     edi, [r10+34h]
                xor     ebx, eax
                mov     ebp, r9d
                xor     ebp, ebx
                xor     edi, r8d
                xor     edi, ebp
                call    SM4_T
                mov     edi, [r10+30h]
                xor     esi, eax
                xor     edi, esi
                xor     edi, ebp
                call    SM4_T
                mov     edi, ebx
                xor     r8d, eax
                xor     edi, esi
                xor     edi, [r10+2Ch]
                xor     edi, r8d
                call    SM4_T
                mov     edi, esi
                xor     r9d, eax
                xor     edi, r8d
                xor     edi, [r10+28h]
                xor     edi, r9d
                call    SM4_T
                mov     edi, [r10+24h]
                mov     ebp, r9d
                xor     ebx, eax
                xor     ebp, ebx
                xor     edi, r8d
                xor     edi, ebp
                call    SM4_T
                mov     edi, [r10+20h]
                xor     esi, eax
                xor     edi, esi
                xor     edi, ebp
                call    SM4_T
                mov     edi, ebx
                xor     r8d, eax
                xor     edi, esi
                xor     edi, [r10+1Ch]
                xor     edi, r8d
                call    SM4_T
                mov     edi, esi
                xor     r9d, eax
                xor     edi, r8d
                xor     edi, [r10+18h]
                xor     edi, r9d
                call    SM4_T
                mov     edi, [r10+14h]
                xor     ebx, eax
                mov     ebp, r9d
                xor     ebp, ebx
                xor     edi, r8d
                xor     edi, ebp
                call    SM4_T
                mov     edi, [r10+10h]
                xor     esi, eax
                xor     edi, esi
                xor     edi, ebp
                call    SM4_T
                mov     edi, ebx
                xor     r8d, eax
                xor     edi, esi
                xor     edi, [r10+0Ch]
                xor     edi, r8d
                call    SM4_T_slow
                mov     edi, esi
                xor     r9d, eax
                xor     edi, r8d
                xor     edi, [r10+8]
                xor     edi, r9d
                call    SM4_T_slow
                mov     edi, [r10+4]
                mov     r12d, r9d
                xor     ebx, eax
                xor     r12d, ebx
                xor     edi, r8d
                xor     edi, r12d
                call    SM4_T_slow
                mov     edi, [r10]
                xor     esi, eax
                mov     ebp, esi
                xor     edi, esi
                xor     edi, r12d
                call    SM4_T_slow
                mov     edi, r8d
                mov     rsi, r11
                xor     edi, eax
                call    ns_put32
                mov     edi, ebp
                lea     rsi, [r11+4]
                call    ns_put32
                mov     edi, ebx
                lea     rsi, [r11+8]
                call    ns_put32
                pop     rbx
                pop     rbp
                lea     rsi, [r11+0Ch]
                mov     edi, r9d
                pop     r12
                jmp     ns_put32
; } // starts at 4E0659

; =============== S U B R O U T I N E =======================================
global ossl_sm3_init
; __int64 __fastcall ossl_sm3_init(SM3_CTX *c)
ossl_sm3_init:                          ; CODE XREF: ossl_sm3_init_+A↑j
                                        ; sub_5181FA+17↓p
; __unwind {
                lea     rsi, [rdi+20h]
                mov     rdx, rdi
                xor     eax, eax
                mov     ecx, 13h
                mov     rdi, rsi
                rep stosd
                mov     rax, 4914B2B9A96F30BCh
                mov     [rdx], rax
                mov     rax, 0DA8A0600172442D7h
                mov     [rdx+8], rax
                mov     rax, 163138AA7380166Fh
                mov     [rdx+10h], rax
                mov     rax, 0B0FB0E4EE38DEE4Dh
                mov     [rdx+18h], rax
                mov     eax, 1
                retn
; } // starts at 4DDB33

; =============== S U B R O U T I N E =======================================
global ossl_sm3_update
; __int64 __fastcall ossl_sm3_update(SM3_CTX *ctx, char *p, unsigned __int64)
ossl_sm3_update:                        ; CODE XREF: ossl_sm3_update_+22↑j

; __unwind {
                test    rdx, rdx
                jz      loc_4E0101
                push    r13
                mov     r8d, edx
                lea     eax, 0[rdx*8]
                push    r12
                push    rbp
                mov     rbp, rdi
                push    rbx
                mov     rbx, rdx
                push    rcx
                add     eax, [rdi+20h]
                jnb     short loc_4E0039
                inc     dword[rdi+24h]

loc_4E0039:                             ; CODE XREF: ossl_sm3_update+23↑j
                mov     rdx, rbx
                mov     [rbp+20h], eax
                shr     rdx, 1Dh
                add     [rbp+24h], edx
                mov     edx, [rbp+68h]
                test    rdx, rdx
                jz      short loc_4E00B6
                lea     r12, [rbp+28h]
                lea     r13, [rbx+rdx]
                lea     rax, [r12+rdx]
                cmp     rbx, 3Fh ; '?'
                ja      short loc_4E0066
                cmp     r13, 3Fh ; '?'
                jbe     short loc_4E00A8

loc_4E0066:                             ; CODE XREF: ossl_sm3_update+4D↑j
                mov     ecx, 40h ; '@'
                mov     rdi, rax
                sub     rcx, rdx
                mov     edx, 1          ; num
                rep movsb
                mov     rdi, rbp        ; ctx
                mov     rbx, rsi
                mov     rsi, r12        ; p
                call    ossl_sm3_block_data_order
                mov     rsi, rbx        ; p
                mov     ecx, 10h
                xor     eax, eax
                mov     rdi, r12
                lea     rbx, [r13-40h]
                mov     dword[rbp+68h], 0
                rep stosd
                cmp     rbx, 3Fh ; '?'
                jbe     short loc_4E00E0
                jmp     short loc_4E00BC
; ---------------------------------------------------------------------------

loc_4E00A8:                             ; CODE XREF: ossl_sm3_update+53↑j
                mov     rdi, rax
                mov     rcx, rbx
                rep movsb
                add     [rbp+68h], r8d
                jmp     short loc_4E00F4
; ---------------------------------------------------------------------------

loc_4E00B6:                             ; CODE XREF: ossl_sm3_update+3B↑j
                cmp     rbx, 3Fh ; '?'
                jbe     short loc_4E00E5

loc_4E00BC:                             ; CODE XREF: ossl_sm3_update+95↑j
                mov     rdx, rbx
                mov     rdi, rbp        ; ctx
                mov     [rsp+28h+-28h], rsi
                shr     rdx, 6          ; num
                call    ossl_sm3_block_data_order
                mov     rax, rbx
                mov     rsi, [rsp+28h+-28h]
                and     rax, 0FFFFFFFFFFFFFFC0h
                add     rsi, rax
                sub     rbx, rax

loc_4E00E0:                             ; CODE XREF: ossl_sm3_update+93↑j
                test    rbx, rbx
                jz      short loc_4E00F4

loc_4E00E5:                             ; CODE XREF: ossl_sm3_update+A9↑j
                mov     [rbp+68h], ebx
                add     rbp, 28h ; '('
                mov     rcx, rbx
                mov     rdi, rbp
                rep movsb

loc_4E00F4:                             ; CODE XREF: ossl_sm3_update+A3↑j
                                        ; ossl_sm3_update+D2↑j
                pop     rdx
                mov     eax, 1
                pop     rbx
                pop     rbp
                pop     r12
                pop     r13
                retn
; ---------------------------------------------------------------------------

loc_4E0101:                             ; CODE XREF: ossl_sm3_update+3↑j
                mov     eax, 1
                retn
; } // starts at 4E0011

; =============== S U B R O U T I N E =======================================
global ossl_sm3_final
; __int64 __fastcall ossl_sm3_final(unsigned __int8 *md, SM3_CTX *c)
ossl_sm3_final:                         ; CODE XREF: ossl_sm3_final_+10↑j
                                        ; sub_51825E+2D↓p
; __unwind {
                push    r12
                lea     r12, [rsi+28h]
                push    rbp
                mov     rbp, rdi
                push    rbx
                mov     edi, [rsi+68h]
                mov     rbx, rsi
                mov     byte[rsi+rdi+28h], 80h
                inc     rdi
                cmp     rdi, 38h ; '8'
                jbe     short loc_4E0155
                lea     rdx, [r12+rdi]
                mov     ecx, 40h ; '@'
                xor     eax, eax
                mov     rsi, r12        ; p
                sub     rcx, rdi
                mov     rdi, rdx
                mov     edx, 1          ; num
                rep stosb
                mov     rdi, rbx        ; ctx
                call    ossl_sm3_block_data_order
                xor     edi, edi

loc_4E0155:                             ; CODE XREF: ossl_sm3_final+1D↑j
                lea     rdx, [r12+rdi]
                mov     ecx, 38h ; '8'
                xor     eax, eax
                mov     rsi, r12        ; p
                sub     ecx, edi
                mov     rdi, rdx
                mov     edx, 1          ; num
                rep stosb
                mov     rdi, rbx        ; ctx
                mov     rax, [rbx+20h]
                bswap   rax
                mov     [rbx+60h], rax
                call    ossl_sm3_block_data_order
                mov     dword[rbx+68h], 0
                mov     rdi, r12
                mov     esi, 40h ; '@'
                call    OPENSSL_cleanse
                mov     eax, [rbx]
                bswap   eax
                mov     [rbp+0], eax
                mov     eax, [rbx+4]
                bswap   eax
                mov     [rbp+4], eax
                mov     eax, [rbx+8]
                bswap   eax
                mov     [rbp+8], eax
                mov     eax, [rbx+0Ch]
                bswap   eax
                mov     [rbp+0Ch], eax
                mov     eax, [rbx+10h]
                bswap   eax
                mov     [rbp+10h], eax
                mov     eax, [rbx+14h]
                bswap   eax
                mov     [rbp+14h], eax
                mov     eax, [rbx+18h]
                bswap   eax
                mov     [rbp+18h], eax
                mov     eax, [rbx+1Ch]
                pop     rbx
                bswap   eax
                mov     [rbp+1Ch], eax
                mov     eax, 1
                pop     rbp
                pop     r12
                retn
; } // starts at 4E0111


; =============== S U B R O U T I N E =======================================


; __int64 __fastcall ossl_sm3_block_data_order(SM3_CTX *ctx, const void *p, size_t num)
ossl_sm3_block_data_order:              ; CODE XREF: ossl_sm3_update+70↓p
                                        ; ossl_sm3_update+B9↓p ...

var_B0          equ -0B0h
var_A8          equ -0A8h
W13             equ -9Ch
W14             equ -98h
var_94          equ -94h
var_90          equ -90h
B_new           equ -8Ch
var_88          equ -88h
var_84          equ -84h
W05             equ -80h
W06             equ -7Ch
W07             equ -78h
W08             equ -74h
W09             equ -70h
W10             equ -6Ch
W11             equ -68h
W12             equ -64h
var_60          equ -60h
var_5C          equ -5Ch
var_58          equ -58h
var_54          equ -54h
var_50          equ -50h
var_4C          equ -4Ch
var_48          equ -48h
var_44          equ -44h
var_40          equ -40h
var_3C          equ -3Ch
var_38          equ -38h

; __unwind {
                push    r15
                push    r14
                push    r13
                push    r12
                push    rbp
                push    rbx
                sub     rsp, 8
                mov     [rsp+38h+var_A8], rdi
                mov     [rsp+38h+var_B0], rsi
                mov     [rsp+38h+var_38], rdx

loc_4DDB9F:                             ; CODE XREF: ossl_sm3_block_data_order+247D↓j
                dec     qword [rsp+38h+var_38]
                cmp     qword [rsp+38h+var_38], 0FFFFFFFFFFFFFFFFh
                jz      loc_4E0005
                mov     rax, [rsp+38h+var_A8]
                mov     rbx, [rsp+38h+var_B0]
                mov     eax, [rax]
                mov     edx, [rbx+14h]
                mov     [rsp+38h+var_5C], eax
                mov     rax, [rsp+38h+var_A8]
                bswap   edx
                mov     eax, [rax+4]
                mov     [rsp+38h+var_50], eax
                mov     rax, [rsp+38h+var_A8]
                mov     eax, [rax+8]
                mov     [rsp+38h+var_4C], eax
                mov     rax, [rsp+38h+var_A8]
                mov     eax, [rax+0Ch]
                mov     [rsp+38h+var_40], eax
                mov     rax, [rsp+38h+var_A8]
                mov     eax, [rax+10h]
                mov     [rsp+38h+var_58], eax
                mov     rax, [rsp+38h+var_A8]
                mov     eax, [rax+14h]
                mov     [rsp+38h+var_48], eax
                mov     rax, [rsp+38h+var_A8]
                mov     eax, [rax+18h]
                mov     [rsp+38h+var_44], eax
                mov     rax, [rsp+38h+var_A8]
                mov     eax, [rax+1Ch]
                mov     [rsp+38h+var_3C], eax
                mov     rax, [rsp+38h+var_B0]
                mov     edi, [rax]
                mov     esi, [rax+4]
                mov     r10d, [rax+8]
                mov     ecx, [rax+0Ch]
                mov     eax, [rax+10h]
                mov     [rsp+38h+W05], edx
                bswap   edi
                bswap   esi
                mov     edx, [rbx+18h]
                mov     r9d, [rsp+38h+var_48]
                bswap   ecx
                bswap   r10d
                mov     r8d, [rsp+38h+var_5C]
                xor     r8d, [rsp+38h+var_50]
                bswap   eax
                bswap   edx
                mov     [rsp+38h+W06], edx
                mov     edx, [rbx+1Ch]
                xor     r8d, [rsp+38h+var_4C]
                add     r8d, [rsp+38h+var_40]
                bswap   edx
                mov     [rsp+38h+W07], edx
                mov     edx, [rbx+20h]
                add     qword [rsp+38h+var_B0], 40h ; '@'
                bswap   edx
                mov     [rsp+38h+W08], edx
                mov     edx, [rbx+24h]
                bswap   edx
                mov     [rsp+38h+W09], edx
                mov     edx, [rbx+28h]
                bswap   edx
                mov     [rsp+38h+W10], edx
                mov     edx, [rbx+2Ch]
                bswap   edx
                mov     [rsp+38h+W11], edx
                mov     edx, [rbx+30h]
                bswap   edx
                mov     [rsp+38h+W12], edx
                mov     edx, [rbx+34h]
                bswap   edx
                mov     [rsp+38h+W13], edx
                mov     edx, [rbx+38h]
                bswap   edx
                mov     [rsp+38h+W14], edx
                mov     edx, [rbx+3Ch]
                mov     ebx, [rsp+38h+var_58]
                bswap   edx
                mov     r15d, edx
                mov     edx, [rsp+38h+var_5C]
                xor     r9d, ebx
                xor     r9d, [rsp+38h+var_44]
                add     r9d, [rsp+38h+var_3C]
                rol     edx, 0Ch
                lea     r11d, [rbx+rdx+79CC4519h]
                mov     ebx, [rsp+38h+var_50]
                rol     r11d, 7
                xor     edx, r11d
                add     r9d, r11d
                rol     ebx, 9
                add     edx, r8d
                mov     r8d, edi
                mov     [rsp+38h+B_new], ebx
                mov     ebp, [rsp+38h+var_48]
                xor     r8d, eax
                mov     r14d, [rsp+38h+var_5C]
                add     edx, r8d
                lea     r8d, [r9+rdi]
                xor     edi, [rsp+38h+W07]
                ror     ebp, 0Dh
                mov     r9d, r8d
                mov     r11d, r8d
                mov     r13d, edx
                ror     r11d, 0Fh
                rol     r9d, 9
                xor     r9d, r11d
                rol     r13d, 0Ch
                xor     r9d, r8d
                mov     r8d, [rsp+38h+W13]
                lea     ebx, [r9+r13-0C6775CEh]
                rol     r8d, 0Fh
                rol     ebx, 7
                xor     edi, r8d
                mov     r8d, ecx
                mov     r12d, ebx
                rol     r8d, 7
                mov     r11d, edi
                xor     r8d, [rsp+38h+W10]
                xor     r8d, edi
                rol     r11d, 0Fh
                xor     r8d, r11d
                ror     edi, 9
                mov     r11d, [rsp+38h+W05]
                xor     r8d, edi
                mov     [rsp+38h+var_94], r8d
                mov     r8d, [rsp+38h+var_5C]
                xor     r8d, [rsp+38h+B_new]
                xor     r11d, esi
                add     r11d, [rsp+38h+var_4C]
                xor     r13d, ebx
                xor     r8d, edx
                mov     ebx, [rsp+38h+var_44]
                rol     r14d, 9
                add     r11d, r8d
                lea     r8d, [r11+r13]
                mov     r11d, [rsp+38h+var_58]
                lea     edi, [rbx+rsi]
                xor     esi, [rsp+38h+W08]
                mov     r13d, edx
                xor     r11d, ebp
                xor     r13d, r14d
                xor     r11d, r9d
                xor     r13d, r8d
                add     edi, r11d
                mov     r11d, [rsp+38h+var_58]
                lea     ebx, [rdi+r12]
                mov     edi, ebx
                mov     r12d, ebx
                ror     r11d, 0Dh
                ror     r12d, 0Fh
                rol     edi, 9
                xor     edi, r12d
                xor     edi, ebx
                mov     ebx, [rsp+38h+W14]
                rol     ebx, 0Fh
                xor     esi, ebx
                mov     ebx, eax
                rol     ebx, 7
                mov     r12d, esi
                xor     ebx, [rsp+38h+W11]
                xor     ebx, esi
                rol     r12d, 0Fh
                xor     ebx, r12d
                ror     esi, 9
                mov     r12d, r8d
                xor     ebx, esi
                rol     r12d, 0Ch
                mov     esi, [rsp+38h+W06]
                mov     [rsp+38h+var_90], ebx
                lea     ebx, [rdi+r12-18CEEB9Bh]
                rol     ebx, 7
                xor     esi, r10d
                add     esi, [rsp+38h+B_new]
                add     esi, r13d
                xor     r12d, ebx
                add     ebp, r10d
                xor     r10d, [rsp+38h+W09]
                add     r12d, esi
                mov     esi, r9d
                rol     edx, 9
                mov     r13d, r8d
                xor     esi, r11d
                xor     r13d, edx
                ror     r9d, 0Dh
                xor     esi, edi
                xor     r13d, r12d
                add     esi, ebp
                add     esi, ebx
                mov     ebx, esi
                mov     ebp, esi
                ror     ebp, 0Fh
                rol     ebx, 9
                xor     ebx, ebp
                xor     ebx, esi
                mov     esi, r15d
                rol     esi, 0Fh
                xor     r10d, esi
                mov     esi, [rsp+38h+W05]
                mov     ebp, r10d
                rol     esi, 7
                xor     esi, [rsp+38h+W12]
                rol     ebp, 0Fh
                xor     esi, r10d
                ror     r10d, 9
                xor     esi, ebp
                mov     ebp, r12d
                xor     esi, r10d
                mov     r10d, [rsp+38h+W07]
                rol     ebp, 0Ch
                mov     [rsp+38h+B_new], esi
                lea     esi, [rbx+rbp-319DD735h]
                xor     r10d, ecx
                rol     esi, 7
                add     r14d, r10d
                xor     ebp, esi
                mov     r10d, edi
                add     r14d, r13d
                mov     r13d, r12d
                add     ebp, r14d
                xor     r10d, r9d
                add     r11d, ecx
                xor     ecx, [rsp+38h+W10]
                rol     r8d, 9
                xor     r10d, ebx
                ror     edi, 0Dh
                add     r11d, r10d
                xor     r13d, r8d
                add     r11d, esi
                xor     r13d, ebp
                mov     esi, r11d
                mov     r10d, r11d
                ror     r10d, 0Fh
                rol     esi, 9
                xor     esi, r10d
                mov     r10d, [rsp+38h+var_94]
                xor     esi, r11d
                rol     r10d, 0Fh
                xor     ecx, r10d
                mov     r10d, [rsp+38h+W06]
                mov     r11d, ecx
                rol     r10d, 7
                xor     r10d, [rsp+38h+W13]
                rol     r11d, 0Fh
                xor     r10d, ecx
                ror     ecx, 9
                xor     r10d, r11d
                mov     r11d, ebp
                xor     r10d, ecx
                mov     ecx, [rsp+38h+W08]
                rol     r11d, 0Ch
                mov     [rsp+38h+var_88], r10d
                lea     r10d, [rsi+r11-633BAE69h]
                xor     ecx, eax
                rol     r10d, 7
                add     edx, ecx
                xor     r11d, r10d
                add     edx, r13d
                add     r11d, edx
                mov     edx, ebx
                xor     edx, edi
                xor     edx, esi
                add     r9d, eax
                xor     eax, [rsp+38h+W11]
                rol     r12d, 9
                add     r9d, edx
                ror     ebx, 0Dh
                add     r9d, r10d
                mov     r10d, r9d
                mov     edx, r9d
                ror     edx, 0Fh
                rol     r10d, 9
                xor     r10d, edx
                mov     edx, [rsp+38h+var_90]
                xor     r10d, r9d
                mov     r9d, ebp
                rol     edx, 0Fh
                xor     r9d, r12d
                xor     eax, edx
                mov     edx, [rsp+38h+W07]
                xor     r9d, r11d
                add     edi, [rsp+38h+W05]
                mov     ecx, eax
                mov     r14d, [rsp+38h+W07]
                mov     r13d, [rsp+38h+W08]
                rol     edx, 7
                xor     edx, [rsp+38h+W14]
                rol     ecx, 0Fh
                xor     edx, eax
                ror     eax, 9
                xor     edx, ecx
                mov     ecx, r11d
                xor     edx, eax
                mov     eax, [rsp+38h+W05]
                xor     eax, [rsp+38h+W09]
                rol     ecx, 0Ch
                add     r8d, eax
                mov     eax, esi
                mov     [rsp+38h+var_84], edx
                lea     edx, [r10+rcx+3988A32Fh]
                xor     eax, ebx
                rol     edx, 7
                add     r8d, r9d
                mov     r9d, [rsp+38h+W06]
                xor     eax, r10d
                xor     ecx, edx
                add     edi, eax
                add     r8d, ecx
                mov     ecx, [rsp+38h+B_new]
                add     edi, edx
                rol     ebp, 9
                xor     r9d, [rsp+38h+W10]
                add     ebx, [rsp+38h+W06]
                mov     edx, edi
                mov     eax, edi
                rol     ecx, 0Fh
                add     r12d, r9d
                ror     eax, 0Fh
                rol     edx, 9
                xor     edx, eax
                mov     eax, [rsp+38h+W05]
                xor     eax, [rsp+38h+W12]
                ror     esi, 0Dh
                xor     eax, ecx
                mov     ecx, [rsp+38h+W08]
                xor     edx, edi
                mov     edi, eax
                rol     ecx, 7
                rol     edi, 0Fh
                xor     ecx, r15d
                xor     ecx, eax
                ror     eax, 9
                xor     ecx, edi
                mov     edi, r11d
                rol     r11d, 9
                xor     ecx, eax
                xor     edi, ebp
                mov     [rsp+38h+W05], ecx
                mov     ecx, r8d
                xor     edi, r8d
                rol     ecx, 0Ch
                add     r12d, edi
                mov     edi, [rsp+38h+var_88]
                lea     eax, [rdx+rcx+7311465Eh]
                rol     eax, 7
                xor     ecx, eax
                add     r12d, ecx
                mov     ecx, r10d
                xor     ecx, esi
                xor     ecx, edx
                add     ebx, ecx
                add     ebx, eax
                ror     r10d, 0Dh
                xor     r14d, [rsp+38h+W11]
                add     esi, [rsp+38h+W07]
                mov     eax, ebx
                mov     ecx, ebx
                rol     edi, 0Fh
                add     ebp, r14d
                ror     ecx, 0Fh
                rol     eax, 9
                xor     eax, ecx
                mov     ecx, [rsp+38h+W06]
                xor     ecx, [rsp+38h+W13]
                xor     ecx, edi
                mov     edi, [rsp+38h+W09]
                xor     eax, ebx
                mov     r9d, ecx
                rol     edi, 7
                xor     edi, [rsp+38h+var_94]
                rol     r9d, 0Fh
                xor     edi, ecx
                ror     ecx, 9
                xor     edi, r9d
                mov     r9d, r8d
                rol     r8d, 9
                xor     edi, ecx
                mov     ecx, r12d
                xor     r9d, r11d
                rol     ecx, 0Ch
                mov     [rsp+38h+W06], edi
                xor     r9d, r12d
                lea     edi, [rax+rcx-19DD7344h]
                add     ebp, r9d
                rol     edi, 7
                xor     ecx, edi
                add     ebp, ecx
                mov     ecx, edx
                ror     edx, 0Dh
                xor     ecx, r10d
                xor     ecx, eax
                add     esi, ecx
                lea     ecx, [rsi+rdi]
                mov     esi, ecx
                mov     edi, ecx
                ror     edi, 0Fh
                rol     esi, 9
                xor     esi, edi
                mov     edi, [rsp+38h+var_84]
                xor     r13d, [rsp+38h+W12]
                xor     esi, ecx
                mov     ecx, [rsp+38h+W07]
                xor     ecx, [rsp+38h+W14]
                add     r11d, r13d
                rol     edi, 0Fh
                add     r10d, [rsp+38h+W08]
                mov     r13d, ebp
                xor     ecx, edi
                mov     edi, [rsp+38h+W10]
                mov     r9d, ecx
                rol     edi, 7
                xor     edi, [rsp+38h+var_90]
                rol     r9d, 0Fh
                xor     edi, ecx
                ror     ecx, 9
                xor     edi, r9d
                mov     r9d, r12d
                rol     r12d, 9
                xor     edi, ecx
                mov     ecx, ebp
                xor     r9d, r8d
                rol     ecx, 0Ch
                mov     [rsp+38h+W07], edi
                xor     r9d, ebp
                lea     edi, [rsi+rcx-33BAE687h]
                add     r11d, r9d
                rol     edi, 7
                xor     ecx, edi
                add     r11d, ecx
                mov     ecx, eax
                ror     eax, 0Dh
                xor     ecx, edx
                xor     ecx, esi
                add     r10d, ecx
                lea     ecx, [r10+rdi]
                mov     r10d, ecx
                mov     edi, ecx
                ror     edi, 0Fh
                rol     r10d, 9
                xor     r10d, edi
                xor     r10d, ecx
                mov     ecx, [rsp+38h+W08]
                mov     edi, [rsp+38h+W05]
                mov     r14d, [rsp+38h+W09]
                xor     ecx, r15d
                rol     edi, 0Fh
                add     edx, [rsp+38h+W09]
                xor     r14d, [rsp+38h+W13]
                xor     ecx, edi
                mov     edi, [rsp+38h+W11]
                xor     r13d, r12d
                add     r8d, r14d
                mov     r9d, ecx
                xor     r13d, r11d
                rol     ebp, 9
                mov     r14d, [rsp+38h+W11]
                rol     edi, 7
                xor     edi, [rsp+38h+B_new]
                rol     r9d, 0Fh
                add     r8d, r13d
                xor     edi, ecx
                ror     ecx, 9
                mov     r13d, r11d
                xor     edi, r9d
                xor     edi, ecx
                mov     ecx, esi
                ror     esi, 0Dh
                mov     [rsp+38h+W08], edi
                mov     edi, r11d
                xor     ecx, eax
                rol     edi, 0Ch
                xor     ecx, r10d
                lea     ebx, [r10+rdi-6775CD0Dh]
                add     edx, ecx
                rol     ebx, 7
                add     edx, ebx
                xor     edi, ebx
                mov     ecx, edx
                mov     ebx, edx
                add     r8d, edi
                ror     ecx, 0Fh
                rol     ebx, 9
                mov     r9d, r8d
                xor     ebx, ecx
                mov     ecx, [rsp+38h+W06]
                xor     ebx, edx
                mov     edx, [rsp+38h+W09]
                xor     edx, [rsp+38h+var_94]
                rol     ecx, 0Fh
                xor     edx, ecx
                mov     ecx, [rsp+38h+W12]
                mov     edi, edx
                rol     ecx, 7
                xor     ecx, [rsp+38h+var_88]
                rol     edi, 0Fh
                add     eax, [rsp+38h+W10]
                rol     r9d, 0Ch
                xor     ecx, edx
                ror     edx, 9
                xor     r13d, ebp
                xor     ecx, edi
                xor     r13d, r8d
                rol     r11d, 9
                xor     ecx, edx
                lea     edx, [rbx+r9+311465E7h]
                mov     [rsp+38h+W09], ecx
                mov     ecx, [rsp+38h+W10]
                rol     edx, 7
                xor     ecx, [rsp+38h+W14]
                xor     r9d, edx
                add     r12d, ecx
                mov     ecx, r10d
                ror     r10d, 0Dh
                xor     ecx, esi
                add     r12d, r13d
                mov     r13d, r8d
                xor     ecx, ebx
                add     r12d, r9d
                mov     r9d, [rsp+38h+W12]
                add     eax, ecx
                add     eax, edx
                mov     edx, eax
                mov     ecx, eax
                ror     ecx, 0Fh
                rol     edx, 9
                xor     edx, ecx
                mov     ecx, [rsp+38h+W07]
                xor     edx, eax
                mov     eax, [rsp+38h+W10]
                xor     eax, [rsp+38h+var_90]
                rol     ecx, 0Fh
                xor     eax, ecx
                mov     ecx, [rsp+38h+W13]
                mov     edi, eax
                rol     ecx, 7
                xor     ecx, [rsp+38h+var_84]
                xor     ecx, eax
                rol     edi, 0Fh
                add     esi, [rsp+38h+W11]
                xor     r14d, r15d
                xor     ecx, edi
                ror     eax, 9
                mov     edi, r12d
                xor     r13d, r11d
                xor     ecx, eax
                rol     edi, 0Ch
                xor     r13d, r12d
                add     ebp, r14d
                mov     [rsp+38h+W10], ecx
                mov     ecx, ebx
                lea     eax, [rdx+rdi+6228CBCEh]
                add     ebp, r13d
                rol     eax, 7
                xor     ecx, r10d
                rol     r8d, 9
                mov     r13d, r12d
                xor     ecx, edx
                xor     edi, eax
                ror     ebx, 0Dh
                add     esi, ecx
                add     ebp, edi
                add     esi, eax
                mov     r14d, ebp
                mov     eax, esi
                mov     ecx, esi
                ror     ecx, 0Fh
                rol     eax, 9
                xor     eax, ecx
                mov     ecx, [rsp+38h+W11]
                xor     ecx, [rsp+38h+B_new]
                xor     eax, esi
                mov     esi, [rsp+38h+W08]
                rol     esi, 0Fh
                xor     ecx, esi
                mov     esi, [rsp+38h+W14]
                mov     edi, ecx
                rol     esi, 7
                xor     esi, [rsp+38h+W05]
                rol     edi, 0Fh
                xor     esi, ecx
                xor     esi, edi
                ror     ecx, 9
                mov     edi, ebp
                xor     r13d, r8d
                rol     edi, 0Ch
                xor     esi, ecx
                mov     ecx, edx
                xor     r13d, ebp
                mov     [rsp+38h+W11], esi
                xor     ecx, ebx
                xor     r9d, [rsp+38h+var_94]
                rol     r12d, 9
                xor     ecx, eax
                add     r10d, [rsp+38h+W12]
                add     r11d, r9d
                ror     edx, 0Dh
                lea     esi, [rax+rdi-3BAE6864h]
                add     r10d, ecx
                add     r11d, r13d
                rol     esi, 7
                add     r10d, esi
                xor     edi, esi
                add     r11d, edi
                mov     esi, r10d
                mov     edi, [rsp+38h+W09]
                mov     ecx, r10d
                ror     ecx, 0Fh
                rol     esi, 9
                xor     esi, ecx
                rol     edi, 0Fh
                mov     ecx, [rsp+38h+W12]
                xor     ecx, [rsp+38h+var_88]
                xor     ecx, edi
                mov     edi, r15d
                xor     esi, r10d
                rol     edi, 7
                mov     r9d, ecx
                xor     edi, [rsp+38h+W06]
                xor     edi, ecx
                rol     r9d, 0Fh
                xor     edi, r9d
                ror     ecx, 9
                mov     r9d, r11d
                xor     edi, ecx
                mov     ecx, [rsp+38h+W13]
                xor     ecx, [rsp+38h+var_90]
                rol     r9d, 0Ch
                add     r8d, ecx
                mov     ecx, eax
                add     ebx, [rsp+38h+W13]
                mov     [rsp+38h+W12], edi
                xor     ecx, edx
                lea     r10d, [rsi+r9-775CD0C7h]
                xor     r14d, r12d
                rol     ebp, 9
                xor     ecx, esi
                rol     r10d, 7
                mov     edi, [rsp+38h+W10]
                xor     r14d, r11d
                add     ebx, ecx
                xor     r9d, r10d
                add     r8d, r14d
                mov     r14d, r11d
                rol     edi, 0Fh
                add     ebx, r10d
                add     r8d, r9d
                ror     eax, 0Dh
                mov     r10d, ebx
                mov     ecx, ebx
                ror     ecx, 0Fh
                rol     r10d, 9
                xor     r10d, ecx
                mov     ecx, [rsp+38h+W13]
                xor     ecx, [rsp+38h+var_84]
                xor     ecx, edi
                mov     edi, [rsp+38h+var_94]
                xor     r10d, ebx
                mov     ebx, [rsp+38h+W14]
                mov     r9d, ecx
                rol     edi, 7
                xor     edi, [rsp+38h+W07]
                rol     r9d, 0Fh
                xor     edi, ecx
                ror     ecx, 9
                xor     edi, r9d
                xor     edi, ecx
                mov     [rsp+38h+W13], edi
                mov     edi, r8d
                rol     edi, 0Ch
                lea     ecx, [r10+rdi+11465E73h]
                rol     ecx, 7
                xor     ebx, [rsp+38h+B_new]
                xor     r14d, ebp
                add     edx, [rsp+38h+W14]
                xor     r14d, r8d
                add     r12d, ebx
                xor     edi, ecx
                rol     r11d, 9
                add     r12d, r14d
                mov     r14d, r8d
                add     r12d, edi
                mov     edi, esi
                xor     r14d, r11d
                ror     esi, 0Dh
                xor     edi, eax
                xor     edi, r10d
                add     edx, edi
                add     edx, ecx
                mov     ecx, edx
                mov     edi, edx
                ror     edi, 0Fh
                rol     ecx, 9
                xor     ecx, edi
                mov     edi, [rsp+38h+W11]
                xor     ecx, edx
                mov     edx, [rsp+38h+W14]
                xor     edx, [rsp+38h+W05]
                rol     edi, 0Fh
                xor     edx, edi
                mov     edi, [rsp+38h+var_90]
                mov     r9d, edx
                rol     edi, 7
                xor     edi, [rsp+38h+W08]
                rol     r9d, 0Fh
                xor     edi, edx
                ror     edx, 9
                xor     edi, r9d
                mov     r9d, r12d
                xor     edi, edx
                rol     r9d, 0Ch
                mov     edx, [rsp+38h+var_88]
                lea     ebx, [rcx+r9+228CBCE6h]
                mov     [rsp+38h+W14], edi
                rol     ebx, 7
                xor     r14d, r12d
                xor     edx, r15d
                add     eax, r15d
                add     ebp, edx
                mov     edx, r10d
                xor     r9d, ebx
                ror     r10d, 0Dh
                xor     edx, esi
                add     ebp, r14d
                xor     edx, ecx
                add     ebp, r9d
                mov     r9d, r8d
                mov     r8d, r12d
                add     eax, edx
                rol     r9d, 9
                or      r8d, ebp
                add     eax, ebx
                and     r8d, r9d
                mov     ebx, eax
                mov     edx, eax
                mov     r13d, r8d
                mov     r8d, r12d
                ror     edx, 0Fh
                rol     ebx, 9
                and     r8d, ebp
                xor     ebx, edx
                mov     edx, [rsp+38h+W06]
                xor     ebx, eax
                mov     eax, [rsp+38h+W12]
                xor     edx, r15d
                rol     eax, 0Fh
                xor     edx, eax
                mov     eax, [rsp+38h+B_new]
                mov     edi, edx
                rol     eax, 7
                xor     eax, [rsp+38h+W09]
                rol     edi, 0Fh
                xor     eax, edx
                ror     edx, 9
                xor     eax, edi
                xor     eax, edx
                mov     edx, ebp
                rol     edx, 0Ch
                mov     [rsp+38h+var_60], eax
                lea     eax, [rbx+rdx-62758579h]
                rol     eax, 7
                or      r8d, r13d
                mov     r13d, [rsp+38h+var_94]
                xor     r13d, [rsp+38h+var_84]
                add     r11d, r13d
                xor     edx, eax
                add     esi, [rsp+38h+var_94]
                mov     edi, [rsp+38h+var_94]
                add     r11d, r8d
                add     esi, eax
                mov     r8d, [rsp+38h+W13]
                xor     edi, [rsp+38h+W07]
                lea     r13d, [r11+rdx]
                mov     edx, ecx
                mov     r11d, ebp
                rol     r12d, 9
                rol     r8d, 0Fh
                xor     edx, r10d
                or      r11d, r13d
                ror     ecx, 0Dh
                and     edx, ebx
                xor     edi, r8d
                xor     edx, r10d
                add     esi, edx
                mov     eax, esi
                mov     edx, esi
                ror     edx, 0Fh
                rol     eax, 9
                xor     eax, edx
                mov     edx, [rsp+38h+var_88]
                xor     eax, esi
                mov     esi, edi
                rol     edx, 7
                xor     edx, [rsp+38h+W10]
                rol     esi, 0Fh
                xor     edx, edi
                ror     edi, 9
                xor     edx, esi
                mov     esi, r11d
                mov     r11d, ebp
                xor     edx, edi
                mov     edi, r13d
                and     esi, r12d
                and     r11d, r13d
                rol     edi, 0Ch
                mov     [rsp+38h+var_94], edx
                lea     edx, [rax+rdi+3B14F50Fh]
                rol     edx, 7
                or      r11d, esi
                mov     esi, [rsp+38h+var_90]
                xor     esi, [rsp+38h+W05]
                lea     r8d, [rsi+r9]
                mov     esi, ebx
                add     r10d, [rsp+38h+var_90]
                ror     ebx, 0Dh
                xor     esi, ecx
                add     r10d, edx
                add     r8d, r11d
                xor     edi, edx
                and     esi, eax
                mov     r11d, ebx
                mov     ebx, [rsp+38h+W14]
                add     edi, r8d
                xor     esi, ecx
                rol     ebp, 9
                add     r10d, esi
                rol     ebx, 0Fh
                mov     esi, [rsp+38h+var_90]
                xor     esi, [rsp+38h+W08]
                mov     r15d, r10d
                mov     edx, r10d
                xor     esi, ebx
                mov     ebx, [rsp+38h+var_88]
                ror     edx, 0Fh
                rol     r15d, 9
                mov     r8d, esi
                xor     r15d, edx
                mov     edx, [rsp+38h+var_84]
                rol     r8d, 0Fh
                xor     r15d, r10d
                rol     edx, 7
                xor     edx, [rsp+38h+W11]
                xor     edx, esi
                ror     esi, 9
                xor     edx, r8d
                mov     r8d, r13d
                xor     edx, esi
                or      r8d, edi
                and     r8d, ebp
                mov     [rsp+38h+var_90], edx
                mov     edx, edi
                rol     edx, 0Ch
                mov     r10d, r8d
                mov     r8d, r13d
                lea     esi, [r15+rdx+7629EA1Eh]
                and     r8d, edi
                rol     esi, 7
                or      r8d, r10d
                mov     r10d, [rsp+38h+B_new]
                xor     r10d, [rsp+38h+W06]
                add     r12d, r10d
                xor     edx, esi
                add     ecx, [rsp+38h+B_new]
                mov     r10d, [rsp+38h+B_new]
                add     r12d, r8d
                add     ecx, esi
                xor     r10d, [rsp+38h+W09]
                mov     r8d, edi
                add     r12d, edx
                mov     edx, eax
                rol     r13d, 9
                xor     edx, r11d
                or      r8d, r12d
                ror     eax, 0Dh
                mov     r9d, r12d
                and     edx, r15d
                xor     edx, r11d
                add     ecx, edx
                mov     edx, [rsp+38h+W05]
                mov     r14d, ecx
                mov     esi, ecx
                ror     esi, 0Fh
                rol     r14d, 9
                xor     r14d, esi
                mov     esi, [rsp+38h+var_60]
                rol     edx, 7
                xor     edx, [rsp+38h+W12]
                xor     r14d, ecx
                rol     esi, 0Fh
                xor     r10d, esi
                mov     ecx, r10d
                xor     edx, r10d
                ror     r10d, 9
                rol     ecx, 0Fh
                xor     edx, ecx
                mov     ecx, r8d
                mov     r8d, edi
                xor     edx, r10d
                and     ecx, r13d
                mov     r10d, [rsp+38h+var_94]
                mov     [rsp+38h+B_new], edx
                mov     edx, r12d
                rol     edx, 0Ch
                lea     esi, [r14+rdx-13AC2BC4h]
                rol     esi, 7
                and     r8d, r12d
                add     ebx, r11d
                rol     r10d, 0Fh
                or      r8d, ecx
                mov     ecx, [rsp+38h+var_88]
                xor     ecx, [rsp+38h+W07]
                xor     edx, esi
                add     ebp, ecx
                add     ebx, esi
                mov     ecx, [rsp+38h+var_88]
                xor     ecx, [rsp+38h+W10]
                add     ebp, r8d
                xor     ecx, r10d
                rol     edi, 9
                add     ebp, edx
                mov     edx, r15d
                ror     r15d, 0Dh
                xor     edx, eax
                or      r9d, ebp
                and     edx, r14d
                xor     edx, eax
                lea     r11d, [rdx+rbx]
                mov     edx, [rsp+38h+W06]
                mov     ebx, r11d
                mov     esi, r11d
                ror     esi, 0Fh
                rol     ebx, 9
                xor     ebx, esi
                rol     edx, 7
                mov     esi, ecx
                xor     edx, [rsp+38h+W13]
                xor     edx, ecx
                rol     esi, 0Fh
                xor     ebx, r11d
                xor     edx, esi
                ror     ecx, 9
                mov     esi, ebp
                xor     edx, ecx
                rol     esi, 0Ch
                mov     ecx, r9d
                mov     r9d, r12d
                mov     [rsp+38h+var_88], edx
                lea     r10d, [rbx+rsi-27585787h]
                mov     edx, r14d
                and     ecx, edi
                rol     r10d, 7
                and     r9d, ebp
                xor     edx, r15d
                add     eax, [rsp+38h+var_84]
                and     edx, ebx
                add     eax, r10d
                xor     esi, r10d
                or      r9d, ecx
                mov     ecx, [rsp+38h+var_84]
                xor     edx, r15d
                xor     ecx, [rsp+38h+W08]
                rol     r12d, 9
                add     eax, edx
                add     r13d, ecx
                ror     r14d, 0Dh
                mov     r10d, eax
                mov     edx, eax
                add     r13d, r9d
                ror     edx, 0Fh
                rol     r10d, 9
                lea     r9d, [r13+rsi+0]
                xor     r10d, edx
                mov     edx, [rsp+38h+var_90]
                mov     esi, r9d
                xor     r10d, eax
                mov     eax, [rsp+38h+var_84]
                xor     eax, [rsp+38h+W11]
                rol     edx, 0Fh
                xor     eax, edx
                mov     edx, [rsp+38h+W07]
                mov     ecx, eax
                rol     edx, 7
                xor     edx, [rsp+38h+W14]
                rol     ecx, 0Fh
                xor     edx, eax
                ror     eax, 9
                xor     edx, ecx
                mov     ecx, ebp
                xor     edx, eax
                or      ecx, r9d
                mov     [rsp+38h+var_84], edx
                mov     edx, r9d
                and     ecx, r12d
                rol     edx, 0Ch
                mov     r11d, ecx
                mov     ecx, ebp
                lea     eax, [r10+rdx-4EB0AF0Dh]
                rol     eax, 7
                and     ecx, r9d
                add     r15d, [rsp+38h+W05]
                rol     ebp, 9
                or      ecx, r11d
                mov     r11d, [rsp+38h+W05]
                xor     r11d, [rsp+38h+W09]
                xor     edx, eax
                add     edi, r11d
                add     r15d, eax
                add     edi, ecx
                lea     r11d, [rdi+rdx]
                mov     edx, ebx
                ror     ebx, 0Dh
                xor     edx, r14d
                or      esi, r11d
                and     edx, r10d
                mov     ecx, edx
                xor     ecx, r14d
                lea     edx, [rcx+r15]
                mov     ecx, [rsp+38h+B_new]
                mov     r15d, edx
                mov     eax, edx
                ror     eax, 0Fh
                rol     r15d, 9
                xor     r15d, eax
                rol     ecx, 0Fh
                mov     eax, [rsp+38h+W05]
                xor     eax, [rsp+38h+W12]
                xor     r15d, edx
                mov     edx, [rsp+38h+W08]
                xor     eax, ecx
                mov     ecx, eax
                rol     edx, 7
                xor     edx, [rsp+38h+var_60]
                rol     ecx, 0Fh
                xor     edx, eax
                ror     eax, 9
                xor     edx, ecx
                mov     ecx, r11d
                xor     edx, eax
                rol     ecx, 0Ch
                mov     eax, esi
                mov     esi, r9d
                lea     edi, [r15+rcx+629EA1E7h]
                and     eax, ebp
                and     esi, r11d
                mov     [rsp+38h+W05], edx
                rol     edi, 7
                or      esi, eax
                mov     eax, [rsp+38h+W06]
                xor     eax, [rsp+38h+W10]
                add     r12d, eax
                mov     eax, r10d
                add     r14d, [rsp+38h+W06]
                xor     ecx, edi
                xor     eax, ebx
                add     r14d, edi
                add     r12d, esi
                mov     esi, r9d
                rol     esi, 9
                and     eax, r15d
                add     r12d, ecx
                mov     ecx, [rsp+38h+W06]
                xor     eax, ebx
                xor     ecx, [rsp+38h+W13]
                ror     r10d, 0Dh
                add     eax, r14d
                mov     r14d, eax
                mov     edi, eax
                ror     edi, 0Fh
                rol     r14d, 9
                xor     r14d, edi
                mov     edi, [rsp+38h+var_88]
                xor     r14d, eax
                mov     eax, [rsp+38h+W09]
                rol     edi, 0Fh
                xor     ecx, edi
                rol     eax, 7
                xor     eax, [rsp+38h+var_94]
                mov     edi, r11d
                mov     edx, ecx
                xor     eax, ecx
                ror     ecx, 9
                or      edi, r12d
                rol     edx, 0Fh
                and     edi, esi
                xor     eax, edx
                mov     r8d, edi
                mov     edx, r15d
                mov     edi, r11d
                xor     eax, ecx
                mov     ecx, r12d
                rol     ecx, 0Ch
                mov     [rsp+38h+W06], eax
                lea     eax, [r14+rcx-3AC2BC32h]
                rol     eax, 7
                and     edi, r12d
                xor     edx, r10d
                rol     r11d, 9
                or      edi, r8d
                and     edx, r14d
                mov     r8d, [rsp+38h+W07]
                xor     r8d, [rsp+38h+W11]
                add     ebx, [rsp+38h+W07]
                xor     edx, r10d
                add     ebp, r8d
                xor     ecx, eax
                add     ebx, eax
                add     ebp, edi
                mov     edi, [rsp+38h+var_84]
                ror     r15d, 0Dh
                add     edx, ebx
                add     ebp, ecx
                mov     ecx, [rsp+38h+W07]
                xor     ecx, [rsp+38h+W14]
                mov     ebx, edx
                mov     eax, edx
                rol     edi, 0Fh
                ror     eax, 0Fh
                rol     ebx, 9
                xor     ecx, edi
                mov     edi, [rsp+38h+W05]
                xor     ebx, eax
                mov     eax, [rsp+38h+W10]
                xor     ebx, edx
                mov     edx, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+var_90]
                rol     edx, 0Fh
                xor     eax, ecx
                ror     ecx, 9
                xor     eax, edx
                mov     edx, ebp
                xor     eax, ecx
                rol     edx, 0Ch
                mov     ecx, r12d
                mov     [rsp+38h+W07], eax
                or      ecx, ebp
                lea     eax, [rbx+rdx-75857863h]
                rol     eax, 7
                and     ecx, r11d
                add     r10d, [rsp+38h+W08]
                rol     edi, 0Fh
                mov     r9d, ecx
                mov     ecx, r12d
                xor     edx, eax
                add     r10d, eax
                and     ecx, ebp
                rol     r12d, 9
                or      ecx, r9d
                mov     r9d, [rsp+38h+W08]
                xor     r9d, [rsp+38h+W12]
                add     r9d, esi
                mov     esi, ebp
                add     r9d, ecx
                mov     ecx, [rsp+38h+W08]
                xor     ecx, [rsp+38h+var_60]
                lea     r13d, [r9+rdx]
                mov     edx, r14d
                xor     ecx, edi
                ror     r14d, 0Dh
                xor     edx, r15d
                or      esi, r13d
                and     edx, ebx
                xor     edx, r15d
                add     edx, r10d
                mov     r10d, edx
                mov     eax, edx
                ror     eax, 0Fh
                rol     r10d, 9
                xor     r10d, eax
                mov     eax, [rsp+38h+W11]
                xor     r10d, edx
                mov     edx, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+B_new]
                rol     edx, 0Fh
                xor     eax, ecx
                ror     ecx, 9
                xor     eax, edx
                mov     edx, [rsp+38h+W09]
                xor     eax, ecx
                mov     ecx, [rsp+38h+W06]
                mov     [rsp+38h+W08], eax
                mov     eax, r13d
                rol     eax, 0Ch
                lea     edi, [r10+rax+14F50F3Bh]
                rol     edi, 7
                and     esi, r12d
                add     r15d, [rsp+38h+W09]
                xor     edx, [rsp+38h+var_94]
                mov     r8d, esi
                mov     esi, ebp
                xor     eax, edi
                add     r15d, edi
                rol     ecx, 0Fh
                and     esi, r13d
                rol     ebp, 9
                or      esi, r8d
                mov     r8d, [rsp+38h+W09]
                xor     r8d, [rsp+38h+W13]
                xor     edx, ecx
                add     r11d, r8d
                mov     ecx, edx
                mov     r8d, r13d
                add     r11d, esi
                rol     ecx, 0Fh
                add     r11d, eax
                mov     eax, ebx
                ror     ebx, 0Dh
                xor     eax, r14d
                or      r8d, r11d
                mov     esi, r11d
                and     eax, r10d
                xor     eax, r14d
                lea     eax, [rax+r15]
                mov     r15d, eax
                mov     edi, eax
                ror     edi, 0Fh
                rol     r15d, 9
                xor     r15d, edi
                mov     edi, r11d
                xor     r15d, eax
                mov     eax, [rsp+38h+W12]
                rol     edi, 0Ch
                rol     eax, 7
                xor     eax, [rsp+38h+var_88]
                xor     eax, edx
                ror     edx, 9
                xor     eax, ecx
                mov     ecx, [rsp+38h+W07]
                xor     eax, edx
                mov     edx, r8d
                mov     r8d, r13d
                mov     [rsp+38h+W09], eax
                lea     eax, [r15+rdi+29EA1E76h]
                rol     eax, 7
                and     edx, ebp
                and     r8d, r11d
                add     r14d, [rsp+38h+W10]
                or      r8d, edx
                mov     edx, [rsp+38h+W10]
                xor     edx, [rsp+38h+W14]
                add     r14d, eax
                rol     ecx, 0Fh
                add     r12d, edx
                mov     edx, r10d
                xor     edi, eax
                rol     r13d, 9
                xor     edx, ebx
                add     r12d, r8d
                ror     r10d, 0Dh
                and     edx, r15d
                lea     r8d, [r12+rdi]
                xor     edx, ebx
                or      esi, r8d
                add     edx, r14d
                mov     r14d, edx
                mov     eax, edx
                ror     eax, 0Fh
                rol     r14d, 9
                xor     r14d, eax
                mov     eax, [rsp+38h+W10]
                xor     eax, [rsp+38h+var_90]
                xor     r14d, edx
                mov     edx, [rsp+38h+W13]
                xor     eax, ecx
                mov     ecx, eax
                rol     edx, 7
                xor     edx, [rsp+38h+var_84]
                rol     ecx, 0Fh
                xor     edx, eax
                ror     eax, 9
                xor     edx, ecx
                mov     ecx, [rsp+38h+W11]
                xor     edx, eax
                mov     [rsp+38h+W10], edx
                mov     edx, r8d
                rol     edx, 0Ch
                lea     eax, [r14+rdx+53D43CECh]
                rol     eax, 7
                and     esi, r13d
                add     ebx, [rsp+38h+W11]
                xor     ecx, [rsp+38h+B_new]
                mov     r12d, esi
                mov     esi, r11d
                xor     edx, eax
                add     ebx, eax
                and     esi, r8d
                rol     r11d, 9
                or      esi, r12d
                mov     r12d, [rsp+38h+W11]
                xor     r12d, [rsp+38h+var_60]
                add     ebp, r12d
                add     ebp, esi
                mov     esi, [rsp+38h+W08]
                add     ebp, edx
                mov     edx, r15d
                ror     r15d, 0Dh
                xor     edx, r10d
                rol     esi, 0Fh
                and     edx, r14d
                xor     ecx, esi
                mov     esi, r8d
                xor     edx, r10d
                add     edx, ebx
                mov     ebx, edx
                mov     eax, edx
                ror     eax, 0Fh
                rol     ebx, 9
                xor     ebx, eax
                mov     eax, [rsp+38h+W14]
                xor     ebx, edx
                mov     edx, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+W05]
                rol     edx, 0Fh
                xor     eax, ecx
                ror     ecx, 9
                xor     eax, edx
                xor     eax, ecx
                mov     [rsp+38h+W11], eax
                mov     eax, ebp
                rol     eax, 0Ch
                lea     edi, [rbx+rax-58578628h]
                rol     edi, 7
                or      esi, ebp
                add     r10d, [rsp+38h+W12]
                and     esi, r11d
                xor     eax, edi
                add     r10d, edi
                mov     ecx, esi
                mov     esi, r8d
                rol     r8d, 9
                and     esi, ebp
                or      esi, ecx
                mov     ecx, [rsp+38h+W12]
                xor     ecx, [rsp+38h+var_94]
                add     r13d, ecx
                mov     ecx, [rsp+38h+W12]
                xor     ecx, [rsp+38h+var_88]
                add     r13d, esi
                add     r13d, eax
                mov     eax, r14d
                ror     r14d, 0Dh
                xor     eax, r15d
                and     eax, ebx
                xor     eax, r15d
                lea     eax, [rax+r10]
                mov     r10d, eax
                mov     edi, eax
                ror     edi, 0Fh
                rol     r10d, 9
                xor     r10d, edi
                mov     edi, [rsp+38h+W09]
                xor     r10d, eax
                mov     eax, [rsp+38h+var_60]
                rol     edi, 0Fh
                xor     ecx, edi
                rol     eax, 7
                xor     eax, [rsp+38h+W06]
                mov     edi, ebp
                mov     edx, ecx
                xor     eax, ecx
                ror     ecx, 9
                rol     edx, 0Fh
                xor     eax, edx
                mov     edx, r13d
                rol     edx, 0Ch
                xor     eax, ecx
                lea     ecx, [r10+rdx+4F50F3B1h]
                mov     [rsp+38h+W12], eax
                mov     eax, ebx
                rol     ecx, 7
                or      edi, r13d
                xor     eax, r14d
                add     r15d, [rsp+38h+W13]
                and     edi, r8d
                and     eax, r10d
                add     r15d, ecx
                xor     edx, ecx
                mov     r9d, edi
                mov     edi, ebp
                xor     eax, r14d
                ror     ebx, 0Dh
                and     edi, r13d
                add     eax, r15d
                rol     ebp, 9
                or      edi, r9d
                mov     r9d, [rsp+38h+W13]
                xor     r9d, [rsp+38h+var_90]
                mov     r15d, eax
                add     r11d, r9d
                mov     ecx, eax
                rol     r15d, 9
                add     r11d, edi
                ror     ecx, 0Fh
                mov     edi, [rsp+38h+W10]
                xor     r15d, ecx
                mov     ecx, [rsp+38h+W13]
                xor     ecx, [rsp+38h+var_84]
                add     r11d, edx
                xor     r15d, eax
                rol     edi, 0Fh
                mov     eax, [rsp+38h+var_94]
                xor     ecx, edi
                rol     eax, 7
                mov     edx, ecx
                xor     eax, [rsp+38h+W07]
                xor     eax, ecx
                rol     edx, 0Fh
                xor     eax, edx
                ror     ecx, 9
                mov     edx, r13d
                xor     eax, ecx
                mov     [rsp+38h+W13], eax
                mov     eax, r11d
                rol     eax, 0Ch
                lea     r9d, [r15+rax-615E189Eh]
                rol     r9d, 7
                or      edx, r11d
                add     r14d, [rsp+38h+W14]
                mov     ecx, edx
                mov     edx, r13d
                xor     eax, r9d
                add     r14d, r9d
                and     ecx, ebp
                and     edx, r11d
                rol     r13d, 9
                or      edx, ecx
                mov     ecx, [rsp+38h+W14]
                xor     ecx, [rsp+38h+B_new]
                add     r8d, ecx
                add     r8d, edx
                mov     edx, [rsp+38h+W14]
                mov     edi, [rsp+38h+W11]
                add     r8d, eax
                mov     eax, r10d
                xor     edx, [rsp+38h+W05]
                ror     r10d, 0Dh
                xor     eax, ebx
                rol     edi, 0Fh
                and     eax, r15d
                xor     edx, edi
                xor     eax, ebx
                mov     ecx, edx
                lea     eax, [rax+r14]
                rol     ecx, 0Fh
                mov     r14d, eax
                mov     r9d, eax
                ror     r9d, 0Fh
                rol     r14d, 9
                xor     r14d, r9d
                xor     r14d, eax
                mov     eax, [rsp+38h+var_90]
                rol     eax, 7
                xor     eax, [rsp+38h+W08]
                xor     eax, edx
                ror     edx, 9
                xor     eax, ecx
                mov     ecx, r11d
                xor     eax, edx
                mov     edx, [rsp+38h+var_60]
                mov     [rsp+38h+W14], eax
                mov     eax, r8d
                rol     eax, 0Ch
                lea     edi, [r14+rax+3D43CEC5h]
                rol     edi, 7
                or      ecx, r8d
                add     ebx, [rsp+38h+var_60]
                xor     edx, [rsp+38h+W06]
                and     ecx, r13d
                xor     eax, edi
                add     ebx, edi
                mov     r9d, ecx
                mov     ecx, r11d
                rol     r11d, 9
                and     ecx, r8d
                or      ecx, r9d
                mov     r9d, [rsp+38h+var_60]
                xor     r9d, [rsp+38h+var_88]
                add     ebp, r9d
                add     ebp, ecx
                add     ebp, eax
                mov     eax, r15d
                ror     r15d, 0Dh
                xor     eax, r10d
                and     eax, r14d
                xor     eax, r10d
                lea     eax, [rax+rbx]
                mov     ebx, eax
                mov     edi, eax
                ror     edi, 0Fh
                rol     ebx, 9
                xor     ebx, edi
                mov     edi, r8d
                xor     ebx, eax
                mov     eax, [rsp+38h+W12]
                rol     eax, 0Fh
                xor     edx, eax
                mov     eax, [rsp+38h+B_new]
                mov     ecx, edx
                rol     eax, 7
                xor     eax, [rsp+38h+W09]
                rol     ecx, 0Fh
                xor     eax, edx
                ror     edx, 9
                xor     eax, ecx
                xor     eax, edx
                mov     edx, ebp
                rol     edx, 0Ch
                mov     [rsp+38h+var_60], eax
                mov     eax, r14d
                lea     ecx, [rbx+rdx+7A879D8Ah]
                rol     ecx, 7
                or      edi, ebp
                xor     eax, r15d
                add     r10d, [rsp+38h+var_94]
                mov     esi, edi
                mov     edi, r8d
                and     eax, ebx
                add     r10d, ecx
                and     esi, r11d
                and     edi, ebp
                xor     eax, r15d
                xor     edx, ecx
                ror     r14d, 0Dh
                or      edi, esi
                mov     esi, [rsp+38h+var_94]
                xor     esi, [rsp+38h+var_84]
                add     eax, r10d
                add     r13d, esi
                rol     r8d, 9
                add     r13d, edi
                mov     r10d, eax
                mov     ecx, eax
                mov     edi, [rsp+38h+var_94]
                ror     ecx, 0Fh
                add     r13d, edx
                rol     r10d, 9
                mov     edx, [rsp+38h+W13]
                xor     r10d, ecx
                xor     edi, [rsp+38h+W07]
                mov     ecx, ebp
                xor     r10d, eax
                rol     edx, 0Fh
                mov     eax, [rsp+38h+var_88]
                xor     edi, edx
                mov     r9d, r10d
                rol     eax, 7
                mov     edx, edi
                xor     eax, [rsp+38h+W10]
                xor     eax, edi
                rol     edx, 0Fh
                xor     eax, edx
                ror     edi, 9
                mov     edx, [rsp+38h+W14]
                xor     eax, edi
                mov     edi, r13d
                mov     [rsp+38h+var_94], eax
                mov     eax, r13d
                rol     eax, 0Ch
                or      ecx, r13d
                add     r15d, [rsp+38h+var_90]
                rol     edx, 0Fh
                and     ecx, r8d
                lea     esi, [r10+rax-0AF0C4ECh]
                mov     r12d, ecx
                mov     ecx, ebp
                rol     esi, 7
                and     ecx, r13d
                xor     eax, esi
                add     r15d, esi
                rol     ebp, 9
                or      ecx, r12d
                mov     r12d, [rsp+38h+var_90]
                xor     r12d, [rsp+38h+W05]
                add     r11d, r12d
                add     r11d, ecx
                add     r11d, eax
                mov     eax, ebx
                ror     ebx, 0Dh
                xor     eax, r14d
                mov     ecx, r11d
                and     eax, r10d
                xor     eax, r14d
                add     eax, r15d
                mov     r15d, eax
                mov     esi, eax
                ror     esi, 0Fh
                rol     r15d, 9
                xor     r15d, esi
                mov     esi, [rsp+38h+var_90]
                xor     esi, [rsp+38h+W08]
                xor     r15d, eax
                mov     eax, [rsp+38h+var_84]
                xor     esi, edx
                mov     edx, esi
                rol     eax, 7
                xor     eax, [rsp+38h+W11]
                rol     edx, 0Fh
                xor     eax, esi
                ror     esi, 9
                xor     eax, edx
                xor     eax, esi
                rol     ecx, 0Ch
                or      edi, r11d
                mov     [rsp+38h+var_90], eax
                mov     eax, r10d
                and     edi, ebp
                add     r14d, [rsp+38h+B_new]
                lea     esi, [r15+rcx-15E189D7h]
                xor     eax, ebx
                mov     edx, edi
                mov     edi, r13d
                rol     esi, 7
                and     eax, r15d
                and     edi, r11d
                mov     r10d, [rsp+38h+B_new]
                add     r14d, esi
                xor     eax, ebx
                or      edi, edx
                xor     ecx, esi
                add     eax, r14d
                mov     edx, [rsp+38h+B_new]
                xor     edx, [rsp+38h+W06]
                ror     r9d, 0Dh
                mov     r14d, eax
                mov     esi, eax
                add     r8d, edx
                mov     edx, [rsp+38h+var_60]
                ror     esi, 0Fh
                rol     r14d, 9
                xor     r10d, [rsp+38h+W09]
                add     r8d, edi
                rol     edx, 0Fh
                xor     r14d, esi
                add     r8d, ecx
                rol     r13d, 9
                xor     r14d, eax
                mov     eax, [rsp+38h+W05]
                xor     r10d, edx
                mov     esi, r11d
                mov     ecx, r10d
                mov     edx, r8d
                rol     eax, 7
                xor     eax, [rsp+38h+W12]
                rol     ecx, 0Fh
                xor     eax, r10d
                xor     eax, ecx
                ror     r10d, 9
                or      esi, r8d
                add     ebx, [rsp+38h+var_88]
                xor     eax, r10d
                rol     edx, 0Ch
                mov     ecx, [rsp+38h+var_88]
                xor     ecx, [rsp+38h+W10]
                mov     [rsp+38h+B_new], eax
                mov     eax, esi
                mov     esi, r11d
                lea     r10d, [r14+rdx-2BC313ADh]
                rol     r10d, 7
                and     eax, r13d
                and     esi, r8d
                rol     r11d, 9
                or      esi, eax
                mov     eax, [rsp+38h+var_88]
                xor     eax, [rsp+38h+W07]
                xor     edx, r10d
                add     ebp, eax
                mov     eax, r15d
                add     ebx, r10d
                ror     r15d, 0Dh
                xor     eax, r9d
                add     ebp, esi
                and     eax, r14d
                lea     r12d, [rbp+rdx+0]
                mov     ebp, [rsp+38h+var_94]
                mov     edx, [rsp+38h+var_90]
                xor     eax, r9d
                add     eax, ebx
                rol     ebp, 0Fh
                mov     ebx, eax
                mov     r10d, eax
                xor     ecx, ebp
                mov     ebp, [rsp+38h+W06]
                ror     r10d, 0Fh
                rol     ebx, 9
                xor     ebx, r10d
                rol     ebp, 7
                xor     ebp, [rsp+38h+W13]
                mov     r10d, r14d
                xor     ebx, eax
                mov     eax, ecx
                xor     ebp, ecx
                rol     eax, 0Fh
                xor     ebp, eax
                ror     ecx, 9
                mov     eax, r12d
                xor     r10d, r15d
                rol     eax, 0Ch
                xor     ebp, ecx
                mov     ecx, r8d
                and     r10d, ebx
                rol     edx, 0Fh
                or      ecx, r12d
                ror     r14d, 0Dh
                mov     [rsp+38h+var_88], ebp
                mov     edi, ecx
                mov     ecx, r8d
                lea     esi, [rbx+rax-57862759h]
                rol     r8d, 9
                and     edi, r11d
                and     ecx, r12d
                rol     esi, 7
                or      ecx, edi
                mov     edi, [rsp+38h+var_84]
                xor     edi, [rsp+38h+W08]
                xor     eax, esi
                add     r13d, edi
                mov     edi, [rsp+38h+var_84]
                add     r13d, ecx
                add     r13d, eax
                mov     eax, r10d
                lea     r10d, [rdi+r9]
                xor     eax, r15d
                add     r10d, esi
                add     r10d, eax
                mov     eax, [rsp+38h+W11]
                mov     r9d, r10d
                mov     esi, r10d
                ror     esi, 0Fh
                xor     eax, edi
                rol     r9d, 9
                xor     eax, edx
                mov     edx, [rsp+38h+W07]
                xor     r9d, esi
                mov     esi, r12d
                mov     ecx, eax
                xor     r9d, r10d
                rol     edx, 7
                xor     edx, [rsp+38h+W14]
                rol     ecx, 0Fh
                xor     edx, eax
                xor     edx, ecx
                ror     eax, 9
                or      esi, r13d
                add     r15d, [rsp+38h+W05]
                xor     edx, eax
                and     esi, r8d
                mov     eax, ebx
                ror     ebx, 0Dh
                mov     [rsp+38h+var_84], edx
                mov     edx, r13d
                mov     r10d, esi
                xor     eax, r14d
                rol     edx, 0Ch
                mov     esi, r12d
                and     eax, r9d
                rol     r12d, 9
                lea     ebp, [r9+rdx+50F3B14Fh]
                and     esi, r13d
                xor     eax, r14d
                rol     ebp, 7
                or      esi, r10d
                mov     r10d, [rsp+38h+W05]
                xor     r10d, [rsp+38h+W09]
                add     r15d, ebp
                add     r11d, r10d
                xor     edx, ebp
                add     eax, r15d
                add     r11d, esi
                mov     r15d, eax
                mov     ebp, eax
                add     r11d, edx
                mov     edx, [rsp+38h+B_new]
                ror     ebp, 0Fh
                rol     r15d, 9
                xor     r15d, ebp
                rol     edx, 0Fh
                xor     r15d, eax
                mov     eax, [rsp+38h+W05]
                xor     eax, [rsp+38h+W12]
                xor     eax, edx
                mov     edx, [rsp+38h+W08]
                mov     ecx, eax
                rol     edx, 7
                xor     edx, [rsp+38h+var_60]
                rol     ecx, 0Fh
                xor     edx, eax
                xor     edx, ecx
                ror     eax, 9
                add     r14d, [rsp+38h+W06]
                mov     ecx, [rsp+38h+W06]
                xor     edx, eax
                mov     eax, r11d
                xor     ecx, [rsp+38h+W13]
                mov     [rsp+38h+W05], edx
                mov     edx, r13d
                rol     eax, 0Ch
                or      edx, r11d
                lea     r10d, [r15+rax-5E189D62h]
                mov     edi, edx
                mov     edx, r13d
                rol     r10d, 7
                and     edi, r12d
                and     edx, r11d
                xor     eax, r10d
                add     r14d, r10d
                or      edx, edi
                mov     edi, [rsp+38h+W06]
                xor     edi, [rsp+38h+W10]
                rol     r13d, 9
                add     r8d, edi
                add     r8d, edx
                add     r8d, eax
                mov     eax, r9d
                ror     r9d, 0Dh
                xor     eax, ebx
                mov     esi, r8d
                and     eax, r15d
                xor     eax, ebx
                add     eax, r14d
                mov     r14d, eax
                mov     r10d, eax
                ror     r10d, 0Fh
                rol     r14d, 9
                xor     r14d, r10d
                xor     r14d, eax
                mov     eax, [rsp+38h+var_88]
                rol     eax, 0Fh
                xor     ecx, eax
                mov     eax, [rsp+38h+W09]
                mov     r10d, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+var_94]
                xor     eax, ecx
                rol     r10d, 0Fh
                add     ebx, [rsp+38h+W07]
                xor     eax, r10d
                ror     ecx, 9
                xor     eax, ecx
                mov     ecx, r11d
                or      ecx, r8d
                mov     [rsp+38h+W06], eax
                mov     eax, r8d
                and     ecx, r13d
                rol     eax, 0Ch
                mov     ebp, ecx
                mov     ecx, r11d
                lea     edx, [r14+rax+43CEC53Dh]
                rol     r11d, 9
                and     ecx, r8d
                rol     edx, 7
                or      ecx, ebp
                mov     ebp, [rsp+38h+W07]
                xor     ebp, [rsp+38h+W11]
                xor     eax, edx
                add     r12d, ebp
                add     ebx, edx
                add     r12d, ecx
                mov     ecx, [rsp+38h+W07]
                xor     ecx, [rsp+38h+W14]
                add     r12d, eax
                mov     eax, r15d
                ror     r15d, 0Dh
                xor     eax, r9d
                and     eax, r14d
                xor     eax, r9d
                add     eax, ebx
                mov     ebx, eax
                mov     edx, eax
                ror     edx, 0Fh
                rol     ebx, 9
                xor     ebx, edx
                xor     ebx, eax
                mov     eax, [rsp+38h+var_84]
                rol     eax, 0Fh
                xor     ecx, eax
                mov     eax, [rsp+38h+W10]
                mov     edx, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+var_90]
                xor     eax, ecx
                rol     edx, 0Fh
                add     r9d, [rsp+38h+W08]
                or      esi, r12d
                xor     eax, edx
                ror     ecx, 9
                mov     edx, r12d
                and     esi, r11d
                xor     eax, ecx
                rol     edx, 0Ch
                mov     edi, esi
                mov     esi, r8d
                mov     [rsp+38h+W07], eax
                mov     eax, r14d
                and     esi, r12d
                mov     ecx, [rsp+38h+W08]
                lea     ebp, [rbx+rdx-78627586h]
                xor     eax, r15d
                or      esi, edi
                xor     ecx, [rsp+38h+var_60]
                rol     ebp, 7
                and     eax, ebx
                mov     edi, [rsp+38h+W08]
                xor     edi, [rsp+38h+W12]
                add     r9d, ebp
                xor     eax, r15d
                xor     edx, ebp
                add     r13d, edi
                add     eax, r9d
                add     r13d, esi
                ror     r14d, 0Dh
                mov     edi, r12d
                mov     r9d, eax
                mov     ebp, eax
                lea     esi, [r13+rdx+0]
                rol     r8d, 9
                ror     ebp, 0Fh
                rol     r9d, 9
                xor     r9d, ebp
                mov     ebp, esi
                xor     r9d, eax
                mov     eax, [rsp+38h+W05]
                rol     eax, 0Fh
                xor     ecx, eax
                mov     eax, [rsp+38h+W11]
                mov     edx, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+B_new]
                xor     eax, ecx
                rol     edx, 0Fh
                or      edi, esi
                xor     eax, edx
                ror     ecx, 9
                and     edi, r8d
                xor     eax, ecx
                mov     ecx, edi
                mov     edi, r12d
                rol     r12d, 9
                mov     [rsp+38h+W08], eax
                mov     eax, esi
                and     edi, esi
                rol     eax, 0Ch
                or      edi, ecx
                mov     ecx, [rsp+38h+W09]
                xor     ecx, [rsp+38h+W13]
                lea     r10d, [r9+rax+0F3B14F5h]
                add     r11d, ecx
                add     r15d, [rsp+38h+W09]
                mov     edx, [rsp+38h+W09]
                rol     r10d, 7
                add     r11d, edi
                xor     edx, [rsp+38h+var_94]
                xor     eax, r10d
                add     r15d, r10d
                add     r11d, eax
                mov     eax, ebx
                ror     ebx, 0Dh
                xor     eax, r14d
                and     eax, r9d
                xor     eax, r14d
                add     r15d, eax
                mov     r10d, r15d
                mov     eax, r15d
                ror     eax, 0Fh
                rol     r10d, 9
                xor     r10d, eax
                mov     eax, [rsp+38h+W06]
                xor     r10d, r15d
                rol     eax, 0Fh
                xor     edx, eax
                mov     eax, [rsp+38h+W12]
                mov     ecx, edx
                rol     eax, 7
                xor     eax, [rsp+38h+var_88]
                rol     ecx, 0Fh
                add     r14d, [rsp+38h+W10]
                xor     eax, edx
                ror     edx, 9
                or      ebp, r11d
                xor     eax, ecx
                mov     ecx, r11d
                and     ebp, r12d
                xor     eax, edx
                rol     ecx, 0Ch
                mov     r13d, ebp
                mov     edx, [rsp+38h+W07]
                mov     [rsp+38h+W09], eax
                mov     eax, r9d
                lea     edi, [r10+rcx+1E7629EAh]
                mov     ebp, esi
                rol     edi, 7
                xor     eax, ebx
                and     ebp, r11d
                rol     edx, 0Fh
                and     eax, r10d
                add     r14d, edi
                xor     ecx, edi
                or      ebp, r13d
                mov     r13d, [rsp+38h+W10]
                xor     eax, ebx
                xor     r13d, [rsp+38h+W14]
                ror     r9d, 0Dh
                add     eax, r14d
                add     r8d, r13d
                rol     esi, 9
                mov     r14d, eax
                mov     edi, eax
                add     r8d, ebp
                ror     edi, 0Fh
                rol     r14d, 9
                add     r8d, ecx
                xor     r14d, edi
                mov     edi, r11d
                xor     r14d, eax
                mov     eax, [rsp+38h+W10]
                xor     eax, [rsp+38h+var_90]
                xor     eax, edx
                mov     edx, [rsp+38h+W13]
                mov     ecx, eax
                rol     edx, 7
                xor     edx, [rsp+38h+var_84]
                rol     ecx, 0Fh
                or      edi, r8d
                xor     edx, eax
                ror     eax, 9
                add     ebx, [rsp+38h+W11]
                xor     edx, ecx
                mov     ecx, [rsp+38h+W11]
                xor     ecx, [rsp+38h+B_new]
                xor     edx, eax
                mov     eax, edi
                mov     edi, r11d
                rol     r11d, 9
                and     eax, esi
                and     edi, r8d
                mov     [rsp+38h+W10], edx
                mov     edx, r8d
                or      edi, eax
                mov     eax, [rsp+38h+W11]
                xor     eax, [rsp+38h+var_60]
                rol     edx, 0Ch
                add     r12d, eax
                mov     eax, r10d
                lea     ebp, [r14+rdx+3CEC53D4h]
                ror     r10d, 0Dh
                xor     eax, r9d
                rol     ebp, 7
                add     r12d, edi
                and     eax, r14d
                add     ebx, ebp
                xor     edx, ebp
                xor     eax, r9d
                add     r12d, edx
                add     eax, ebx
                mov     ebx, eax
                mov     ebp, eax
                ror     ebp, 0Fh
                rol     ebx, 9
                xor     ebx, ebp
                xor     ebx, eax
                mov     eax, [rsp+38h+W08]
                rol     eax, 0Fh
                xor     ecx, eax
                mov     eax, [rsp+38h+W14]
                add     r9d, [rsp+38h+W12]
                mov     edx, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+W05]
                rol     edx, 0Fh
                xor     eax, ecx
                ror     ecx, 9
                xor     eax, edx
                xor     eax, ecx
                mov     ecx, r8d
                or      ecx, r12d
                mov     [rsp+38h+W11], eax
                mov     eax, r12d
                and     ecx, r11d
                rol     eax, 0Ch
                mov     ebp, ecx
                mov     ecx, r8d
                lea     r13d, [rbx+rax+79D8A7A8h]
                rol     r8d, 9
                and     ecx, r12d
                rol     r13d, 7
                or      ecx, ebp
                mov     ebp, [rsp+38h+W12]
                xor     ebp, [rsp+38h+var_94]
                xor     eax, r13d
                add     esi, ebp
                add     r9d, r13d
                mov     ebp, r12d
                add     esi, ecx
                mov     ecx, [rsp+38h+W12]
                xor     ecx, [rsp+38h+var_88]
                add     esi, eax
                mov     eax, r14d
                ror     r14d, 0Dh
                xor     eax, r10d
                and     eax, ebx
                xor     eax, r10d
                add     eax, r9d
                mov     r9d, eax
                mov     r13d, eax
                ror     r13d, 0Fh
                rol     r9d, 9
                xor     r9d, r13d
                xor     r9d, eax
                mov     eax, [rsp+38h+W09]
                rol     eax, 0Fh
                or      ebp, esi
                xor     ecx, eax
                mov     eax, [rsp+38h+var_60]
                mov     edx, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+W06]
                rol     edx, 0Fh
                add     r10d, [rsp+38h+W13]
                xor     eax, ecx
                ror     ecx, 9
                xor     eax, edx
                mov     edx, ebp
                mov     ebp, r12d
                rol     r12d, 9
                xor     eax, ecx
                mov     ecx, esi
                and     edx, r8d
                and     ebp, esi
                mov     [rsp+38h+W12], eax
                rol     ecx, 0Ch
                mov     eax, ebx
                or      ebp, edx
                lea     r15d, [r9+rcx-0C4EB0B0h]
                xor     eax, r14d
                mov     edx, [rsp+38h+W13]
                xor     edx, [rsp+38h+var_90]
                rol     r15d, 7
                and     eax, r9d
                add     r11d, edx
                ror     ebx, 0Dh
                xor     eax, r14d
                add     r10d, r15d
                xor     ecx, r15d
                add     r11d, ebp
                add     r10d, eax
                mov     eax, [rsp+38h+W10]
                add     r11d, ecx
                mov     ecx, [rsp+38h+W13]
                mov     r15d, r10d
                mov     edx, r10d
                ror     edx, 0Fh
                rol     r15d, 9
                xor     r15d, edx
                xor     r15d, r10d
                xor     ecx, [rsp+38h+var_84]
                rol     eax, 0Fh
                add     r14d, [rsp+38h+W14]
                xor     ecx, eax
                mov     eax, [rsp+38h+var_94]
                mov     edx, ecx
                rol     eax, 7
                xor     eax, [rsp+38h+W07]
                rol     edx, 0Fh
                xor     eax, ecx
                ror     ecx, 9
                xor     eax, edx
                mov     edx, esi
                or      edx, r11d
                xor     eax, ecx
                and     edx, r12d
                mov     [rsp+38h+var_54], eax
                mov     eax, r11d
                mov     r10d, edx
                mov     edx, esi
                rol     eax, 0Ch
                and     edx, r11d
                lea     r13d, [r15+rax-189D615Fh]
                rol     esi, 9
                or      edx, r10d
                mov     r10d, [rsp+38h+W14]
                xor     r10d, [rsp+38h+B_new]
                rol     r13d, 7
                add     r8d, r10d
                xor     eax, r13d
                add     r14d, r13d
                add     r8d, edx
                mov     edx, [rsp+38h+W14]
                lea     r10d, [r8+rax]
                mov     eax, r9d
                ror     r9d, 0Dh
                mov     r8d, r11d
                xor     eax, ebx
                mov     ecx, r10d
                and     eax, r15d
                xor     eax, ebx
                add     eax, r14d
                mov     r14d, eax
                mov     r13d, eax
                ror     r13d, 0Fh
                rol     r14d, 9
                xor     r14d, r13d
                xor     r14d, eax
                mov     eax, [rsp+38h+W11]
                xor     edx, [rsp+38h+W05]
                rol     ecx, 0Ch
                add     ebx, [rsp+38h+var_60]
                or      r8d, r10d
                rol     eax, 0Fh
                xor     edx, eax
                mov     eax, [rsp+38h+var_90]
                mov     edi, edx
                rol     eax, 7
                xor     eax, [rsp+38h+W08]
                rol     edi, 0Fh
                xor     eax, edx
                ror     edx, 9
                xor     eax, edi
                mov     edi, r8d
                mov     r8d, r11d
                rol     r11d, 9
                xor     eax, edx
                mov     edx, r15d
                and     edi, esi
                and     r8d, r10d
                xor     edx, r9d
                mov     [rsp+38h+W14], eax
                or      r8d, edi
                mov     edi, [rsp+38h+var_60]
                lea     eax, [r14+rcx-313AC2BDh]
                and     edx, r14d
                xor     edi, [rsp+38h+var_88]
                ror     r15d, 0Dh
                rol     eax, 7
                xor     edx, r9d
                add     r12d, edi
                add     ebx, eax
                xor     ecx, eax
                add     r12d, r8d
                mov     r8d, r10d
                lea     eax, [rdx+rbx]
                add     r12d, ecx
                mov     edx, [rsp+38h+var_60]
                mov     ebp, eax
                mov     ebx, eax
                mov     edi, r12d
                ror     ebx, 0Fh
                rol     ebp, 9
                xor     ebp, ebx
                xor     ebp, eax
                mov     eax, [rsp+38h+W12]
                xor     edx, [rsp+38h+W06]
                or      r8d, r12d
                rol     edi, 0Ch
                add     r9d, [rsp+38h+var_94]
                rol     eax, 0Fh
                xor     edx, eax
                mov     eax, [rsp+38h+B_new]
                mov     ecx, edx
                rol     eax, 7
                xor     eax, [rsp+38h+W09]
                rol     ecx, 0Fh
                xor     eax, edx
                ror     edx, 9
                xor     eax, ecx
                mov     ecx, r8d
                mov     r8d, r10d
                rol     r10d, 9
                and     ecx, r11d
                and     r8d, r12d
                xor     eax, edx
                or      r8d, ecx
                mov     ecx, [rsp+38h+var_94]
                xor     ecx, [rsp+38h+var_84]
                mov     [rsp+38h+W13], eax
                add     esi, ecx
                mov     ecx, r14d
                lea     edx, [rbp+rdi-62758579h]
                ror     r14d, 0Dh
                xor     ecx, r15d
                rol     edx, 7
                add     esi, r8d
                and     ecx, ebp
                add     r9d, edx
                xor     edi, edx
                xor     ecx, r15d
                lea     r8d, [rsi+rdi]
                mov     edi, [rsp+38h+var_94]
                xor     edi, [rsp+38h+W07]
                lea     edx, [rcx+r9]
                mov     r9d, r8d
                mov     r13d, edx
                mov     eax, edx
                ror     eax, 0Fh
                rol     r13d, 9
                xor     r13d, eax
                mov     eax, [rsp+38h+var_54]
                xor     r13d, edx
                rol     eax, 0Fh
                rol     r9d, 0Ch
                add     r15d, [rsp+38h+var_90]
                xor     edi, eax
                mov     eax, [rsp+38h+var_88]
                lea     esi, [r13+r9+3B14F50Fh]
                mov     edx, edi
                rol     esi, 7
                rol     eax, 7
                xor     eax, [rsp+38h+W10]
                rol     edx, 0Fh
                add     r15d, esi
                xor     eax, edi
                ror     edi, 9
                xor     r9d, esi
                xor     eax, edx
                mov     edx, r12d
                xor     eax, edi
                or      edx, r8d
                mov     [rsp+38h+var_60], eax
                mov     eax, [rsp+38h+var_90]
                mov     edi, edx
                mov     edx, r12d
                xor     eax, [rsp+38h+W05]
                and     edi, r10d
                and     edx, r8d
                add     r11d, eax
                mov     eax, ebp
                or      edx, edi
                ror     ebp, 0Dh
                xor     eax, r14d
                add     r11d, edx
                and     eax, r13d
                lea     edi, [r11+r9]
                mov     r9d, r12d
                xor     eax, r14d
                rol     r9d, 9
                mov     r11d, edi
                lea     esi, [rax+r15]
                mov     r15d, [rsp+38h+var_54]
                mov     edx, esi
                mov     eax, esi
                ror     eax, 0Fh
                rol     edx, 9
                xor     edx, eax
                mov     eax, [rsp+38h+var_90]
                xor     eax, [rsp+38h+W08]
                xor     edx, esi
                mov     esi, [rsp+38h+W14]
                rol     esi, 0Fh
                xor     eax, esi
                mov     esi, r8d
                rol     r11d, 0Ch
                add     r14d, [rsp+38h+B_new]
                or      esi, edi
                mov     [rsp+38h+var_94], eax
                lea     ecx, [rdx+r11+7629EA1Eh]
                mov     eax, esi
                mov     esi, r8d
                rol     ecx, 7
                and     eax, r9d
                and     esi, edi
                add     r14d, ecx
                xor     r11d, ecx
                or      esi, eax
                mov     eax, [rsp+38h+B_new]
                xor     eax, [rsp+38h+W06]
                rol     r8d, 9
                add     r10d, eax
                mov     eax, r13d
                xor     eax, ebp
                add     r10d, esi
                and     eax, edx
                lea     esi, [r10+r11]
                xor     eax, ebp
                mov     r12d, esi
                add     ebp, [rsp+38h+var_88]
                lea     ecx, [rax+r14]
                mov     eax, r13d
                rol     r12d, 0Ch
                mov     r13d, [rsp+38h+var_88]
                mov     r10d, ecx
                mov     r11d, ecx
                ror     eax, 0Dh
                mov     r14d, edi
                ror     r11d, 0Fh
                rol     r10d, 9
                xor     r10d, r11d
                mov     r11d, [rsp+38h+W13]
                xor     r10d, ecx
                mov     ecx, [rsp+38h+B_new]
                xor     ecx, [rsp+38h+W09]
                rol     r11d, 0Fh
                lea     ebx, [r10+r12]
                xor     ecx, r11d
                mov     r11d, edx
                xor     r11d, eax
                mov     [rsp+38h+var_90], ecx
                lea     ecx, [rbx-13AC2BC4h]
                and     r11d, r10d
                rol     ecx, 7
                xor     r11d, eax
                add     r11d, ebp
                mov     ebp, [rsp+38h+var_60]
                add     r11d, ecx
                xor     r13d, [rsp+38h+W10]
                xor     r15d, [rsp+38h+W13]
                xor     ecx, r12d
                rol     ebp, 0Fh
                rol     r14d, 9
                add     ebx, 3D43CEC5h
                xor     ebp, r13d
                mov     r13d, [rsp+38h+W06]
                rol     ebx, 7
                xor     r12d, ebx
                rol     r13d, 7
                xor     r13d, r15d
                mov     r15d, ebp
                xor     r13d, ebp
                rol     r15d, 0Fh
                xor     r13d, r15d
                ror     ebp, 9
                mov     r15d, esi
                xor     r13d, ebp
                mov     ebp, edi
                or      r15d, r14d
                and     r14d, esi
                mov     [rsp+38h+B_new], r13d
                mov     r13d, edi
                and     ebp, esi
                and     r15d, r8d
                or      r13d, esi
                or      r14d, r15d
                and     r13d, r8d
                or      r13d, ebp
                mov     ebp, [rsp+38h+var_88]
                xor     ebp, [rsp+38h+W07]
                add     ebp, [rsp+38h+B_new]
                add     r9d, ebp
                mov     ebp, esi
                add     r13d, r9d
                mov     r9d, r11d
                add     r13d, r14d
                add     r13d, ecx
                mov     ecx, edx
                add     r12d, r13d
                ror     ecx, 0Dh
                ror     r9d, 0Fh
                xor     ecx, eax
                or      ebp, r12d
                ror     edi, 0Eh
                and     ecx, r10d
                rol     edx, 6
                xor     ecx, eax
                add     ecx, [rsp+38h+W13]
                add     ebx, ecx
                mov     ecx, r11d
                rol     ecx, 9
                xor     ecx, r9d
                xor     ecx, r11d
                add     ebx, ecx
                mov     r11d, ebx
                mov     ecx, ebx
                ror     ecx, 0Fh
                rol     r11d, 9
                xor     r11d, ecx
                mov     ecx, ebp
                mov     ebp, esi
                xor     r11d, ebx
                and     ecx, edi
                and     ebp, r12d
                mov     ebx, r12d
                or      ebp, ecx
                rol     ebx, 0Ch
                mov     ecx, [rsp+38h+var_84]
                xor     ecx, [rsp+38h+W08]
                lea     r9d, [r11+rbx-27585787h]
                add     r8d, ecx
                mov     ecx, r10d
                add     eax, [rsp+38h+var_84]
                xor     ecx, edx
                rol     r9d, 7
                add     r8d, ebp
                xor     ebx, r9d
                and     ecx, r11d
                add     r8d, ebx
                xor     ecx, edx
                add     r9d, eax
                rol     esi, 9
                add     r9d, ecx
                ror     r10d, 0Dh
                add     edx, [rsp+38h+W05]
                mov     r14d, r9d
                mov     ecx, r9d
                ror     ecx, 0Fh
                rol     r14d, 9
                xor     r14d, ecx
                mov     ecx, r8d
                xor     r14d, r9d
                mov     r9d, r12d
                rol     ecx, 0Ch
                or      r9d, r8d
                lea     eax, [r14+rcx-4EB0AF0Dh]
                and     r9d, esi
                rol     eax, 7
                mov     r13d, r9d
                mov     r9d, r12d
                xor     ecx, eax
                add     eax, edx
                and     r9d, r8d
                rol     r12d, 9
                or      r9d, r13d
                mov     r13d, [rsp+38h+W05]
                xor     r13d, [rsp+38h+W09]
                add     edi, r13d
                add     edi, r9d
                add     edi, ecx
                mov     ecx, r11d
                ror     r11d, 0Dh
                xor     ecx, r10d
                mov     r15d, edi
                and     ecx, r14d
                rol     r15d, 0Ch
                xor     ecx, r10d
                add     eax, ecx
                mov     ebp, eax
                mov     edx, eax
                ror     edx, 0Fh
                rol     ebp, 9
                xor     ebp, edx
                xor     ebp, eax
                mov     eax, r8d
                lea     edx, [rbp+r15+629EA1E7h]
                rol     edx, 7
                or      eax, edi
                add     r10d, [rsp+38h+W06]
                and     eax, r12d
                xor     r15d, edx
                add     r10d, edx
                mov     r9d, eax
                mov     eax, r8d
                rol     r8d, 9
                and     eax, edi
                or      eax, r9d
                mov     r9d, [rsp+38h+W06]
                xor     r9d, [rsp+38h+W10]
                add     esi, r9d
                add     esi, eax
                mov     eax, edi
                add     r15d, esi
                mov     esi, r14d
                ror     r14d, 0Dh
                xor     esi, r11d
                or      eax, r15d
                mov     ebx, r15d
                and     esi, ebp
                and     eax, r8d
                rol     ebx, 0Ch
                xor     esi, r11d
                add     esi, r10d
                mov     r10d, esi
                mov     edx, esi
                ror     edx, 0Fh
                rol     r10d, 9
                xor     r10d, edx
                xor     r10d, esi
                mov     esi, eax
                mov     eax, edi
                and     eax, r15d
                lea     r9d, [r10+rbx-3AC2BC32h]
                or      eax, esi
                mov     esi, [rsp+38h+W07]
                xor     esi, [rsp+38h+W11]
                rol     r9d, 7
                add     r12d, esi
                xor     ebx, r9d
                mov     esi, ebp
                add     r12d, eax
                add     r12d, ebx
                xor     esi, r14d
                add     r11d, [rsp+38h+W07]
                rol     edi, 9
                and     esi, r10d
                add     r11d, r9d
                ror     ebp, 0Dh
                xor     esi, r14d
                add     r14d, [rsp+38h+W08]
                lea     r9d, [rsi+r11]
                mov     r11d, r9d
                mov     eax, r9d
                ror     eax, 0Fh
                rol     r11d, 9
                xor     r11d, eax
                mov     eax, r15d
                or      eax, r12d
                xor     r11d, r9d
                mov     r9d, r12d
                and     eax, edi
                rol     r9d, 0Ch
                mov     ebx, eax
                mov     eax, r15d
                lea     esi, [r11+r9-75857863h]
                rol     r15d, 9
                and     eax, r12d
                rol     esi, 7
                or      eax, ebx
                mov     ebx, [rsp+38h+W08]
                xor     ebx, [rsp+38h+W12]
                xor     r9d, esi
                add     r8d, ebx
                add     r14d, esi
                add     r8d, eax
                mov     eax, r12d
                lea     ebx, [r8+r9]
                mov     r8d, r10d
                ror     r10d, 0Dh
                xor     r8d, ebp
                mov     ecx, ebx
                mov     edx, ebx
                and     r8d, r11d
                xor     r8d, ebp
                add     r8d, r14d
                mov     r14d, r8d
                mov     esi, r8d
                ror     esi, 0Fh
                rol     r14d, 9
                xor     r14d, esi
                or      eax, ebx
                rol     ecx, 0Ch
                mov     esi, r11d
                and     eax, r15d
                xor     r14d, r8d
                xor     esi, r10d
                add     ebp, [rsp+38h+W09]
                mov     r13d, eax
                mov     eax, r12d
                and     esi, r14d
                rol     r12d, 9
                lea     r8d, [r14+rcx+14F50F3Bh]
                and     eax, ebx
                xor     esi, r10d
                ror     r11d, 0Dh
                rol     r8d, 7
                or      eax, r13d
                mov     r13d, [rsp+38h+W09]
                xor     r13d, [rsp+38h+var_54]
                add     ebp, r8d
                add     edi, r13d
                xor     ecx, r8d
                add     esi, ebp
                add     edi, eax
                lea     r13d, [rdi+rcx]
                mov     ebp, esi
                mov     r8d, esi
                ror     r8d, 0Fh
                or      edx, r13d
                rol     ebp, 9
                xor     ebp, r8d
                mov     eax, edx
                mov     r8d, r13d
                mov     edx, ebx
                xor     ebp, esi
                and     eax, r12d
                rol     r8d, 0Ch
                and     edx, r13d
                lea     esi, [rbp+r8+29EA1E76h]
                or      edx, eax
                mov     eax, [rsp+38h+W10]
                xor     eax, [rsp+38h+W14]
                rol     esi, 7
                add     r15d, eax
                add     r15d, edx
                xor     r8d, esi
                add     r10d, [rsp+38h+W10]
                rol     ebx, 9
                add     r15d, r8d
                mov     r8d, r14d
                add     r10d, esi
                mov     esi, r13d
                xor     r8d, r11d
                or      esi, r15d
                mov     ecx, r15d
                ror     r14d, 0Dh
                and     r8d, ebp
                mov     eax, esi
                mov     esi, r13d
                rol     ecx, 0Ch
                xor     r8d, r11d
                and     eax, ebx
                and     esi, r15d
                add     r11d, [rsp+38h+W11]
                add     r8d, r10d
                or      esi, eax
                mov     eax, [rsp+38h+W11]
                xor     eax, [rsp+38h+W13]
                mov     edi, r8d
                mov     r10d, r8d
                add     r12d, eax
                mov     eax, ebp
                ror     r10d, 0Fh
                rol     edi, 9
                xor     eax, r14d
                add     r12d, esi
                xor     edi, r10d
                mov     esi, r15d
                xor     edi, r8d
                lea     edx, [rdi+rcx+53D43CECh]
                and     eax, edi
                rol     edx, 7
                xor     eax, r14d
                xor     ecx, edx
                add     edx, r11d
                add     edx, eax
                add     r12d, ecx
                rol     r13d, 9
                add     r14d, [rsp+38h+W12]
                mov     r8d, edx
                mov     r11d, edx
                or      esi, r12d
                mov     r10d, r12d
                ror     r11d, 0Fh
                rol     r8d, 9
                mov     eax, esi
                mov     esi, r15d
                xor     r8d, r11d
                and     eax, r13d
                and     esi, r12d
                ror     ebp, 0Dh
                xor     r8d, edx
                mov     edx, [rsp+38h+var_60]
                xor     edx, [rsp+38h+W12]
                or      esi, eax
                add     ebx, edx
                rol     r10d, 0Ch
                mov     r11d, r12d
                add     ebx, esi
                mov     esi, edi
                lea     ecx, [r8+r10-58578628h]
                ror     edi, 0Dh
                xor     esi, ebp
                rol     ecx, 7
                and     esi, r8d
                add     r14d, ecx
                xor     r10d, ecx
                xor     esi, ebp
                lea     eax, [rbx+r10]
                mov     r10d, [rsp+38h+var_84]
                lea     ecx, [rsi+r14]
                mov     r9d, eax
                mov     r14d, r15d
                rol     r9d, 0Ch
                mov     esi, ecx
                mov     edx, ecx
                rol     r14d, 9
                ror     edx, 0Fh
                rol     esi, 9
                xor     esi, edx
                mov     edx, [rsp+38h+var_94]
                rol     r10d, 7
                xor     r10d, [rsp+38h+W11]
                xor     esi, ecx
                xor     r10d, [rsp+38h+var_54]
                lea     ebx, [rsi+r9+4F50F3B1h]
                rol     ebx, 7
                xor     r10d, [rsp+38h+var_94]
                rol     edx, 0Fh
                or      r11d, eax
                xor     r10d, edx
                mov     edx, [rsp+38h+var_94]
                and     r11d, r14d
                add     ebp, [rsp+38h+var_54]
                add     ebp, ebx
                xor     r9d, ebx
                ror     r15d, 0Bh
                ror     edx, 9
                xor     r10d, edx
                mov     edx, r12d
                rol     r12d, 9
                add     r13d, r10d
                mov     r10d, r8d
                and     edx, eax
                xor     r10d, edi
                or      r11d, edx
                and     r10d, esi
                add     r13d, r11d
                mov     r11d, esi
                xor     r10d, edi
                lea     edx, [r13+r9+0]
                add     r10d, ebp
                mov     ebp, r14d
                mov     ebx, edx
                mov     r13d, edx
                mov     r9d, r10d
                mov     ecx, r10d
                and     ebp, edx
                ror     ecx, 0Fh
                rol     r9d, 9
                xor     r9d, ecx
                lea     ecx, [rdi+r15+3D43CEC5h]
                xor     r9d, r10d
                mov     r10d, r14d
                rol     ecx, 7
                or      r10d, edx
                xor     r15d, ecx
                add     r15d, [rsp+38h+B_new]
                and     r10d, eax
                add     r12d, r15d
                or      ebp, r10d
                mov     r10d, r9d
                add     ebp, r12d
                xor     r11d, r9d
                add     ecx, [rsp+38h+W13]
                ror     r8d, 0Dh
                rol     ebx, 9
                and     r11d, edi
                add     r8d, ecx
                ror     r10d, 0Dh
                xor     r11d, esi
                ror     r13d, 0Bh
                add     r8d, r11d
                lea     r12d, [r10+r13-615E189Eh]
                mov     r11d, r8d
                mov     ecx, r8d
                rol     r12d, 7
                ror     ecx, 0Fh
                rol     r11d, 9
                xor     r13d, r12d
                xor     r11d, ecx
                mov     ecx, [rsp+38h+W05]
                xor     r11d, r8d
                mov     r8d, [rsp+38h+var_90]
                rol     ecx, 7
                xor     ecx, [rsp+38h+W12]
                xor     ecx, [rsp+38h+W14]
                rol     r8d, 0Fh
                xor     ecx, [rsp+38h+var_90]
                xor     ecx, r8d
                mov     r8d, [rsp+38h+var_90]
                ror     r8d, 9
                xor     ecx, r8d
                mov     r8d, eax
                add     ecx, r14d
                or      r8d, ebx
                mov     r14d, eax
                and     r8d, ebp
                and     r14d, ebx
                or      r8d, r14d
                add     r8d, ecx
                mov     ecx, esi
                add     r8d, r13d
                xor     ecx, r11d
                add     edi, [rsp+38h+W14]
                mov     r13d, ebx
                and     ecx, r10d
                add     edi, r12d
                ror     esi, 0Dh
                or      r13d, r8d
                xor     ecx, r11d
                rol     eax, 9
                xor     r10d, esi
                and     ebx, r8d
                add     ecx, edi
                and     r13d, eax
                add     r11d, [rsp+38h+W13]
                add     ebp, [rsp+38h+B_new]
                mov     r12d, ecx
                mov     edi, ecx
                or      ebx, r13d
                ror     edx, 0Eh
                ror     edi, 0Fh
                rol     r12d, 9
                add     ebp, ebx
                mov     rbx, [rsp+38h+var_A8]
                xor     r12d, edi
                mov     edi, r8d
                xor     edx, [rsp+38h+var_4C]
                xor     r8d, [rsp+38h+var_50]
                xor     ecx, r12d
                rol     edi, 0Ch
                mov     [rbx+4], r8d
                lea     r12d, [rcx+rdi+3D43CEC5h]
                and     r10d, ecx
                mov     [rbx+8], edx
                rol     r12d, 7
                xor     r10d, esi
                add     r11d, r12d
                xor     edi, r12d
                add     r10d, r11d
                add     ebp, edi
                xor     ebp, [rsp+38h+var_5C]
                xor     eax, [rsp+38h+var_40]
                mov     [rbx+0Ch], eax
                mov     eax, [rsp+38h+var_58]
                mov     r11d, r10d
                rol     r9d, 6
                rol     r11d, 9
                xor     ecx, [rsp+38h+var_48]
                xor     r9d, [rsp+38h+var_44]
                mov     [rbx], ebp
                xor     eax, r10d
                ror     r10d, 0Fh
                xor     esi, [rsp+38h+var_3C]
                mov     [rbx+14h], ecx
                xor     eax, r11d
                mov     [rbx+18h], r9d
                xor     r10d, eax
                mov     [rbx+1Ch], esi
                mov     [rbx+10h], r10d
                jmp     loc_4DDB9F
; ---------------------------------------------------------------------------

loc_4E0005:                             ; CODE XREF: ossl_sm3_block_data_order+25↑j
                pop     rax
                pop     rbx
                pop     rbp
                pop     r12
                pop     r13
                pop     r14
                pop     r15
                retn
; } // starts at 4DDB83


; =============== S U B R O U T I N E =======================================

; Attributes: library function

; void __fastcall ns_put32(unsigned int, _DWORD *)
ns_put32:                               ; CODE XREF: ossl_sm4_decrypt+2A0↓p
                                        ; ossl_sm4_decrypt+2AB↓p ...
; __unwind {
                bswap   edi
                mov     [rsi], edi
                retn
; } // starts at 4E0212

; =============== S U B R O U T I N E =======================================

; uint32_t __fastcall load_u32_be(const uint8_t *b, uint32_t n)
load_u32_be:                            ; CODE XREF: ossl_sm4_set_key+7↓p
                                        ; ossl_sm4_set_key+19↓p ...
; __unwind {
                lea     eax, [rsi*4]
                mov     rsi, rax
                movzx   eax, byte[rdi+rax]
                lea     edx, [rsi+3]
                movzx   edx, byte[rdi+rdx]
                shl     eax, 18h
                or      eax, edx
                lea     edx, [rsi+1]
                add     esi, 2
                movzx   edx, byte[rdi+rdx]
                shl     edx, 10h
                or      eax, edx
                movzx   edx, byte[rdi+rsi]
                shl     edx, 8
                or      eax, edx
                retn
; } // starts at 4E01DF

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall SM4_key_sub(unsigned int)
SM4_key_sub:                            ; CODE XREF: ossl_sm4_set_key+5B↓p
                                        ; ossl_sm4_set_key+72↓p ...
; __unwind {
                call    SM4_T_non_lin_sub
                mov     edx, eax
                ror     eax, 8
                mov     ecx, edx
                rol     ecx, 0Ch
                xor     eax, ecx
                xor     eax, edx
                retn
; } // starts at 4E02AC

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall SM4_T_non_lin_sub(unsigned int)
SM4_T_non_lin_sub:                      ; CODE XREF: SM4_T_slow↓p
                                        ; SM4_key_sub↓p
; __unwind {
                mov     eax, edi
                movzx   ecx, dil
                mov     edx, edi
                shr     eax, 18h
                movzx   ecx, byte SM4_S[rcx]
                movzx   edx, dh
                movzx   eax, byte SM4_S[rax]
                movzx   edx, byte SM4_S[rdx]
                shl     eax, 18h
                shl     edx, 8
                or      eax, ecx
                mov     ecx, edi
                shr     ecx, 10h
                movzx   ecx, cl
                movzx   ecx, byte SM4_S[rcx]
                shl     ecx, 10h
                or      eax, ecx
                or      eax, edx
                retn
; } // starts at 4E0217

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall SM4_T_slow(unsigned int)
SM4_T_slow:                             ; CODE XREF: ossl_sm4_decrypt+42↓p
                                        ; ossl_sm4_decrypt+56↓p ...
; __unwind {
                call    SM4_T_non_lin_sub
                mov     edx, eax
                rol     eax, 0Ah
                mov     ecx, edx
                rol     ecx, 2
                xor     eax, ecx
                mov     ecx, edx
                xor     eax, edx
                ror     ecx, 0Eh
                xor     eax, ecx
                ror     edx, 8
                xor     eax, edx
                retn
; } // starts at 4E0259

; =============== S U B R O U T I N E =======================================


; __int64 __fastcall SM4_T(unsigned int X)
SM4_T:                                  ; CODE XREF: ossl_sm4_decrypt+8D↓p
                                        ; ossl_sm4_decrypt+A1↓p ...
; __unwind {
                mov     eax, edi
                movzx   ecx, dil
                mov     edx, edi
                shr     eax, 18h
                movzx   edx, dh
                mov     eax, SM4_SBOX_T0[rax*4]
                xor     eax, SM4_SBOX_T3[rcx*4]
                mov     ecx, edi
                shr     ecx, 10h
                movzx   ecx, cl
                xor     eax, SM4_SBOX_T1[rcx*4]
                xor     eax, SM4_SBOX_T2[rdx*4]
                retn
; } // starts at 4E0279

; =============== S U B R O U T I N E =======================================

; Attributes: library function

; __int64 __fastcall OPENSSL_cleanse(_BYTE *, unsigned __int64)
OPENSSL_cleanse:                        ; CODE XREF: sub_402802+1BC↑p
                                        ; sub_413FF6+40↑p ...
; __unwind {
                endbr64
                xor     rax, rax
                cmp     rsi, 0Fh
                jnb     short loc_4C5330
                cmp     rsi, 0
                jz      short locret_4C531F

loc_4C5313:                             ; CODE XREF: OPENSSL_cleanse+1D↓j
                                        ; OPENSSL_cleanse+5D↓j
                mov     [rdi], al
                sub     rsi, 1
                lea     rdi, [rdi+1]
                jnz     short loc_4C5313

locret_4C531F:                          ; CODE XREF: OPENSSL_cleanse+11↑j
                rep retn
; ---------------------------------------------------------------------------
                align 10h

loc_4C5330:                             ; CODE XREF: OPENSSL_cleanse+B↑j
                                        ; OPENSSL_cleanse+43↓j
                test    rdi, 7
                jz      short loc_4C5345
                mov     [rdi], al
                lea     rsi, [rsi-1]
                lea     rdi, [rdi+1]
                jmp     short loc_4C5330
; ---------------------------------------------------------------------------

loc_4C5345:                             ; CODE XREF: OPENSSL_cleanse+37↑j
                                        ; OPENSSL_cleanse+57↓j
                mov     [rdi], rax
                lea     rsi, [rsi-8]
                test    rsi, 0FFFFFFFFFFFFFFF8h
                lea     rdi, [rdi+8]
                jnz     short loc_4C5345
                cmp     rsi, 0
                jnz     short loc_4C5313
                rep retn
; } // starts at 4C5300


section .rodata
; char SM4_S[256]
SM4_S           db 0D6h, 90h, 0E9h, 0FEh, 0CCh, 0E1h, 3Dh, 0B7h, 16h, 0B6h
                                        ; DATA XREF: SM4_T_non_lin_sub+B↑r
                                        ; SM4_T_non_lin_sub+15↑r ...
                db 14h, 0C2h, 28h, 0FBh, 2Ch, 5, 2Bh, 67h, 9Ah, 76h, 2Ah
                db 0BEh, 4, 0C3h, 0AAh, 44h, 13h, 26h, 49h, 86h, 6, 99h
                db 9Ch, 42h, 50h, 0F4h, 91h, 0EFh, 98h, 7Ah, 33h, 54h
                db 0Bh, 43h, 0EDh, 0CFh, 0ACh, 62h, 0E4h, 0B3h, 1Ch, 0A9h
                db 0C9h, 8, 0E8h, 95h, 80h, 0DFh, 94h, 0FAh, 75h, 8Fh
                db 3Fh, 0A6h, 47h, 7, 0A7h, 0FCh, 0F3h, 73h, 17h, 0BAh
                db 83h, 59h, 3Ch, 19h, 0E6h, 85h, 4Fh, 0A8h, 68h, 6Bh
                db 81h, 0B2h, 71h, 64h, 0DAh, 8Bh, 0F8h, 0EBh, 0Fh, 4Bh
                db 70h, 56h, 9Dh, 35h, 1Eh, 24h, 0Eh, 5Eh, 63h, 58h, 0D1h
                db 0A2h, 25h, 22h, 7Ch, 3Bh, 1, 21h, 78h, 87h, 0D4h, 0
                db 46h, 57h, 9Fh, 0D3h, 27h, 52h, 4Ch, 36h, 2, 0E7h, 0A0h
                db 0C4h, 0C8h, 9Eh, 0EAh, 0BFh, 8Ah, 0D2h, 40h, 0C7h, 38h
                db 0B5h, 0A3h, 0F7h, 0F2h, 0CEh, 0F9h, 61h, 15h, 0A1h
                db 0E0h, 0AEh, 5Dh, 0A4h, 9Bh, 34h, 1Ah, 55h, 0ADh, 93h
                db 32h, 30h, 0F5h, 8Ch, 0B1h, 0E3h, 1Dh, 0F6h, 0E2h, 2Eh
                db 82h, 66h, 0CAh, 60h, 0C0h, 29h, 23h, 0ABh, 0Dh, 53h
                db 4Eh, 6Fh, 0D5h, 0DBh, 37h, 45h, 0DEh, 0FDh, 8Eh, 2Fh
                db 3, 0FFh, 6Ah, 72h, 6Dh, 6Ch, 5Bh, 51h, 8Dh, 1Bh, 0AFh
                db 92h, 0BBh, 0DDh, 0BCh, 7Fh, 11h, 0D9h, 5Ch, 41h, 1Fh
                db 10h, 5Ah, 0D8h, 0Ah, 0C1h, 31h, 88h, 0A5h, 0CDh, 7Bh
                db 0BDh, 2Dh, 74h, 0D0h, 12h, 0B8h, 0E5h, 0B4h, 0B0h, 89h
                db 69h, 97h, 4Ah, 0Ch, 96h, 77h, 7Eh, 65h, 0B9h, 0F1h
                db 9, 0C5h, 6Eh, 0C6h, 84h, 18h, 0F0h, 7Dh, 0ECh, 3Ah
                db 0DCh, 4Dh, 20h, 79h, 0EEh, 5Fh, 3Eh, 0D7h, 0CBh, 39h
                db 48h

; int CK[]
CK              dd 70E15h, 1C232A31h, 383F464Dh, 545B6269h, 70777E85h
                                        ; DATA XREF: ossl_sm4_set_key+55↑r
                                        ; ossl_sm4_set_key+6C↑r ...
                dd 8C939AA1h, 0A8AFB6BDh, 0C4CBD2D9h, 0E0E7EEF5h, 0FC030A11h
                dd 181F262Dh, 343B4249h, 50575E65h, 6C737A81h, 888F969Dh
                dd 0A4ABB2B9h, 0C0C7CED5h, 0DCE3EAF1h, 0F8FF060Dh, 141B2229h
                dd 30373E45h, 4C535A61h, 686F767Dh, 848B9299h, 0A0A7AEB5h
                dd 0BCC3CAD1h, 0D8DFE6EDh, 0F4FB0209h, 10171E25h, 2C333A41h
                dd 484F565Dh, 646B7279h

; int SM4_SBOX_T3[256]
SM4_SBOX_T3     dd 0D55B5B8Eh, 924242D0h, 0EAA7A74Dh, 0FDFBFB06h, 0CF3333FCh
                                        ; DATA XREF: SM4_T+15↑r
                dd 0E2878765h, 3DF4F4C9h, 0B5DEDE6Bh, 1658584Eh, 0B4DADA6Eh
                dd 14505044h, 0C10B0BCAh, 28A0A088h, 0F8EFEF17h, 2CB0B09Ch
                dd 5141411h, 2BACAC87h, 669D9DFBh, 986A6AF2h, 77D9D9AEh
                dd 2AA8A882h, 0BCFAFA46h, 4101014h, 0C00F0FCFh, 0A8AAAA02h
                dd 45111154h, 134C4C5Fh, 269898BEh, 4825256Dh, 841A1A9Eh
                dd 618181Eh, 9B6666FDh, 9E7272ECh, 4309094Ah, 51414110h
                dd 0F7D3D324h, 934646D5h, 0ECBFBF53h, 9A6262F8h, 7BE9E992h
                dd 33CCCCFFh, 55515104h, 0B2C2C27h, 420D0D4Fh, 0EEB7B759h
                dd 0CC3F3FF3h, 0AEB2B21Ch, 638989EAh, 0E7939374h, 0B1CECE7Fh
                dd 1C70706Ch, 0ABA6A60Dh, 0CA2727EDh, 8202028h, 0EBA3A348h
                dd 975656C1h, 82020280h, 0DC7F7FA3h, 965252C4h, 0F9EBEB12h
                dd 74D5D5A1h, 8D3E3EB3h, 3FFCFCC3h, 0A49A9A3Eh, 461D1D5Bh
                dd 71C1C1Bh, 0A59E9E3Bh, 0FFF3F30Ch, 0F0CFCF3Fh, 72CDCDBFh
                dd 175C5C4Bh, 0B8EAEA52h, 810E0E8Fh, 5865653Dh, 3CF0F0CCh
                dd 1964647Dh, 0E59B9B7Eh, 87161691h, 4E3D3D73h, 0AAA2A208h
                dd 69A1A1C8h, 6AADADC7h, 83060685h, 0B0CACA7Ah, 70C5C5B5h
                dd 659191F4h, 0D96B6BB2h, 892E2EA7h, 0FBE3E318h, 0E8AFAF47h
                dd 0F3C3C33h, 4A2D2D67h, 71C1C1B0h, 5759590Eh, 9F7676E9h
                dd 35D4D4E1h, 1E787866h, 249090B4h, 0E383836h, 5F797926h
                dd 628D8DEFh, 59616138h, 0D2474795h, 0A08A8A2Ah, 259494B1h
                dd 228888AAh, 7DF1F18Ch, 3BECECD7h, 1040405h, 218484A5h
                dd 79E1E198h, 851E1E9Bh, 0D7535384h, 0, 4719195Eh, 565D5D0Bh
                dd 9D7E7EE3h, 0D04F4F9Fh, 279C9CBBh, 5349491Ah, 4D31317Ch
                dd 36D8D8EEh, 208080Ah, 0E49F9F7Bh, 0A2828220h, 0C71313D4h
                dd 0CB2323E8h, 9C7A7AE6h, 0E9ABAB42h, 0BDFEFE43h, 882A2AA2h
                dd 0D14B4B9Ah, 41010140h, 0C41F1FDBh, 38E0E0D8h, 0B7D6D661h
                dd 0A18E8E2Fh, 0F4DFDF2Bh, 0F1CBCB3Ah, 0CD3B3BF6h, 0FAE7E71Dh
                dd 608585E5h, 15545441h, 0A3868625h, 0E3838360h, 0ACBABA16h
                dd 5C757529h, 0A6929234h, 996E6EF7h, 34D0D0E4h, 1A686872h
                dd 54555501h, 0AFB6B619h, 914E4EDFh, 32C8C8FAh, 30C0C0F0h
                dd 0F6D7D721h, 8E3232BCh, 0B3C6C675h, 0E08F8F6Fh, 1D747469h
                dd 0F5DBDB2Eh, 0E18B8B6Ah, 2EB8B896h, 800A0A8Ah, 679999FEh
                dd 0C92B2BE2h, 618181E0h, 0C30303C0h, 29A4A48Dh, 238C8CAFh
                dd 0A9AEAE07h, 0D343439h, 524D4D1Fh, 4F393976h, 6EBDBDD3h
                dd 0D6575781h, 0D86F6FB7h, 37DCDCEBh, 44151551h, 0DD7B7BA6h
                dd 0FEF7F709h, 8C3A3AB6h, 2FBCBC93h, 30C0C0Fh, 0FCFFFF03h
                dd 6BA9A9C2h, 73C9C9BAh, 6CB5B5D9h, 6DB1B1DCh, 5A6D6D37h
                dd 50454515h, 8F3636B9h, 1B6C6C77h, 0ADBEBE13h, 904A4ADAh
                dd 0B9EEEE57h, 0DE7777A9h, 0BEF2F24Ch, 7EFDFD83h, 11444455h
                dd 0DA6767BDh, 5D71712Ch, 40050545h, 1F7C7C63h, 10404050h
                dd 5B696932h, 0DB6363B8h, 0A282822h, 0C20707C5h, 31C4C4F5h
                dd 8A2222A8h, 0A7969631h, 0CE3737F9h, 7AEDED97h, 0BFF6F649h
                dd 2DB4B499h, 75D1D1A4h, 0D3434390h, 1248485Ah, 0BAE2E258h
                dd 0E6979771h, 0B6D2D264h, 0B2C2C270h, 8B2626ADh, 68A5A5CDh
                dd 955E5ECBh, 4B292962h, 0C30303Ch, 945A5ACEh, 76DDDDABh
                dd 7FF9F986h, 649595F1h, 0BBE6E65Dh, 0F2C7C735h, 924242Dh
                dd 0C61717D1h, 6FB9B9D6h, 0C51B1BDEh, 86121294h, 18606078h
                dd 0F3C3C330h, 7CF5F589h, 0EFB3B35Ch, 3AE8E8D2h, 0DF7373ACh
                dd 4C353579h, 208080A0h, 78E5E59Dh, 0EDBBBB56h, 5E7D7D23h
                dd 3EF8F8C6h, 0D45F5F8Bh, 0C82F2FE7h, 39E4E4DDh, 49212168h
; int SM4_SBOX_T1[256]
SM4_SBOX_T1     dd 5B5B8ED5h, 4242D092h, 0A7A74DEAh, 0FBFB06FDh, 3333FCCFh
                                        ; DATA XREF: SM4_T+24↑r
                dd 878765E2h, 0F4F4C93Dh, 0DEDE6BB5h, 58584E16h, 0DADA6EB4h
                dd 50504414h, 0B0BCAC1h, 0A0A08828h, 0EFEF17F8h, 0B0B09C2Ch
                dd 14141105h, 0ACAC872Bh, 9D9DFB66h, 6A6AF298h, 0D9D9AE77h
                dd 0A8A8822Ah, 0FAFA46BCh, 10101404h, 0F0FCFC0h, 0AAAA02A8h
                dd 11115445h, 4C4C5F13h, 9898BE26h, 25256D48h, 1A1A9E84h
                dd 18181E06h, 6666FD9Bh, 7272EC9Eh, 9094A43h, 41411051h
                dd 0D3D324F7h, 4646D593h, 0BFBF53ECh, 6262F89Ah, 0E9E9927Bh
                dd 0CCCCFF33h, 51510455h, 2C2C270Bh, 0D0D4F42h, 0B7B759EEh
                dd 3F3FF3CCh, 0B2B21CAEh, 8989EA63h, 939374E7h, 0CECE7FB1h
                dd 70706C1Ch, 0A6A60DABh, 2727EDCAh, 20202808h, 0A3A348EBh
                dd 5656C197h, 2028082h, 7F7FA3DCh, 5252C496h, 0EBEB12F9h
                dd 0D5D5A174h, 3E3EB38Dh, 0FCFCC33Fh, 9A9A3EA4h, 1D1D5B46h
                dd 1C1C1B07h, 9E9E3BA5h, 0F3F30CFFh, 0CFCF3FF0h, 0CDCDBF72h
                dd 5C5C4B17h, 0EAEA52B8h, 0E0E8F81h, 65653D58h, 0F0F0CC3Ch
                dd 64647D19h, 9B9B7EE5h, 16169187h, 3D3D734Eh, 0A2A208AAh
                dd 0A1A1C869h, 0ADADC76Ah, 6068583h, 0CACA7AB0h, 0C5C5B570h
                dd 9191F465h, 6B6BB2D9h, 2E2EA789h, 0E3E318FBh, 0AFAF47E8h
                dd 3C3C330Fh, 2D2D674Ah, 0C1C1B071h, 59590E57h, 7676E99Fh
                dd 0D4D4E135h, 7878661Eh, 9090B424h, 3838360Eh, 7979265Fh
                dd 8D8DEF62h, 61613859h, 474795D2h, 8A8A2AA0h, 9494B125h
                dd 8888AA22h, 0F1F18C7Dh, 0ECECD73Bh, 4040501h, 8484A521h
                dd 0E1E19879h, 1E1E9B85h, 535384D7h, 0, 19195E47h, 5D5D0B56h
                dd 7E7EE39Dh, 4F4F9FD0h, 9C9CBB27h, 49491A53h, 31317C4Dh
                dd 0D8D8EE36h, 8080A02h, 9F9F7BE4h, 828220A2h, 1313D4C7h
                dd 2323E8CBh, 7A7AE69Ch, 0ABAB42E9h, 0FEFE43BDh, 2A2AA288h
                dd 4B4B9AD1h, 1014041h, 1F1FDBC4h, 0E0E0D838h, 0D6D661B7h
                dd 8E8E2FA1h, 0DFDF2BF4h, 0CBCB3AF1h, 3B3BF6CDh, 0E7E71DFAh
                dd 8585E560h, 54544115h, 868625A3h, 838360E3h, 0BABA16ACh
                dd 7575295Ch, 929234A6h, 6E6EF799h, 0D0D0E434h, 6868721Ah
                dd 55550154h, 0B6B619AFh, 4E4EDF91h, 0C8C8FA32h, 0C0C0F030h
                dd 0D7D721F6h, 3232BC8Eh, 0C6C675B3h, 8F8F6FE0h, 7474691Dh
                dd 0DBDB2EF5h, 8B8B6AE1h, 0B8B8962Eh, 0A0A8A80h, 9999FE67h
                dd 2B2BE2C9h, 8181E061h, 303C0C3h, 0A4A48D29h, 8C8CAF23h
                dd 0AEAE07A9h, 3434390Dh, 4D4D1F52h, 3939764Fh, 0BDBDD36Eh
                dd 575781D6h, 6F6FB7D8h, 0DCDCEB37h, 15155144h, 7B7BA6DDh
                dd 0F7F709FEh, 3A3AB68Ch, 0BCBC932Fh, 0C0C0F03h, 0FFFF03FCh
                dd 0A9A9C26Bh, 0C9C9BA73h, 0B5B5D96Ch, 0B1B1DC6Dh, 6D6D375Ah
                dd 45451550h, 3636B98Fh, 6C6C771Bh, 0BEBE13ADh, 4A4ADA90h
                dd 0EEEE57B9h, 7777A9DEh, 0F2F24CBEh, 0FDFD837Eh, 44445511h
                dd 6767BDDAh, 71712C5Dh, 5054540h, 7C7C631Fh, 40405010h
                dd 6969325Bh, 6363B8DBh, 2828220Ah, 707C5C2h, 0C4C4F531h
                dd 2222A88Ah, 969631A7h, 3737F9CEh, 0EDED977Ah, 0F6F649BFh
                dd 0B4B4992Dh, 0D1D1A475h, 434390D3h, 48485A12h, 0E2E258BAh
                dd 979771E6h, 0D2D264B6h, 0C2C270B2h, 2626AD8Bh, 0A5A5CD68h
                dd 5E5ECB95h, 2929624Bh, 30303C0Ch, 5A5ACE94h, 0DDDDAB76h
                dd 0F9F9867Fh, 9595F164h, 0E6E65DBBh, 0C7C735F2h, 24242D09h
                dd 1717D1C6h, 0B9B9D66Fh, 1B1BDEC5h, 12129486h, 60607818h
                dd 0C3C330F3h, 0F5F5897Ch, 0B3B35CEFh, 0E8E8D23Ah, 7373ACDFh
                dd 3535794Ch, 8080A020h, 0E5E59D78h, 0BBBB56EDh, 7D7D235Eh
                dd 0F8F8C63Eh, 5F5F8BD4h, 2F2FE7C8h, 0E4E4DD39h, 21216849h
; int SM4_SBOX_T2[256]
SM4_SBOX_T2     dd 5B8ED55Bh, 42D09242h, 0A74DEAA7h, 0FB06FDFBh, 33FCCF33h
                                        ; DATA XREF: SM4_T+2B↑r
                dd 8765E287h, 0F4C93DF4h, 0DE6BB5DEh, 584E1658h, 0DA6EB4DAh
                dd 50441450h, 0BCAC10Bh, 0A08828A0h, 0EF17F8EFh, 0B09C2CB0h
                dd 14110514h, 0AC872BACh, 9DFB669Dh, 6AF2986Ah, 0D9AE77D9h
                dd 0A8822AA8h, 0FA46BCFAh, 10140410h, 0FCFC00Fh, 0AA02A8AAh
                dd 11544511h, 4C5F134Ch, 98BE2698h, 256D4825h, 1A9E841Ah
                dd 181E0618h, 66FD9B66h, 72EC9E72h, 94A4309h, 41105141h
                dd 0D324F7D3h, 46D59346h, 0BF53ECBFh, 62F89A62h, 0E9927BE9h
                dd 0CCFF33CCh, 51045551h, 2C270B2Ch, 0D4F420Dh, 0B759EEB7h
                dd 3FF3CC3Fh, 0B21CAEB2h, 89EA6389h, 9374E793h, 0CE7FB1CEh
                dd 706C1C70h, 0A60DABA6h, 27EDCA27h, 20280820h, 0A348EBA3h
                dd 56C19756h, 2808202h, 7FA3DC7Fh, 52C49652h, 0EB12F9EBh
                dd 0D5A174D5h, 3EB38D3Eh, 0FCC33FFCh, 9A3EA49Ah, 1D5B461Dh
                dd 1C1B071Ch, 9E3BA59Eh, 0F30CFFF3h, 0CF3FF0CFh, 0CDBF72CDh
                dd 5C4B175Ch, 0EA52B8EAh, 0E8F810Eh, 653D5865h, 0F0CC3CF0h
                dd 647D1964h, 9B7EE59Bh, 16918716h, 3D734E3Dh, 0A208AAA2h
                dd 0A1C869A1h, 0ADC76AADh, 6858306h, 0CA7AB0CAh, 0C5B570C5h
                dd 91F46591h, 6BB2D96Bh, 2EA7892Eh, 0E318FBE3h, 0AF47E8AFh
                dd 3C330F3Ch, 2D674A2Dh, 0C1B071C1h, 590E5759h, 76E99F76h
                dd 0D4E135D4h, 78661E78h, 90B42490h, 38360E38h, 79265F79h
                dd 8DEF628Dh, 61385961h, 4795D247h, 8A2AA08Ah, 94B12594h
                dd 88AA2288h, 0F18C7DF1h, 0ECD73BECh, 4050104h, 84A52184h
                dd 0E19879E1h, 1E9B851Eh, 5384D753h, 0, 195E4719h, 5D0B565Dh
                dd 7EE39D7Eh, 4F9FD04Fh, 9CBB279Ch, 491A5349h, 317C4D31h
                dd 0D8EE36D8h, 80A0208h, 9F7BE49Fh, 8220A282h, 13D4C713h
                dd 23E8CB23h, 7AE69C7Ah, 0AB42E9ABh, 0FE43BDFEh, 2AA2882Ah
                dd 4B9AD14Bh, 1404101h, 1FDBC41Fh, 0E0D838E0h, 0D661B7D6h
                dd 8E2FA18Eh, 0DF2BF4DFh, 0CB3AF1CBh, 3BF6CD3Bh, 0E71DFAE7h
                dd 85E56085h, 54411554h, 8625A386h, 8360E383h, 0BA16ACBAh
                dd 75295C75h, 9234A692h, 6EF7996Eh, 0D0E434D0h, 68721A68h
                dd 55015455h, 0B619AFB6h, 4EDF914Eh, 0C8FA32C8h, 0C0F030C0h
                dd 0D721F6D7h, 32BC8E32h, 0C675B3C6h, 8F6FE08Fh, 74691D74h
                dd 0DB2EF5DBh, 8B6AE18Bh, 0B8962EB8h, 0A8A800Ah, 99FE6799h
                dd 2BE2C92Bh, 81E06181h, 3C0C303h, 0A48D29A4h, 8CAF238Ch
                dd 0AE07A9AEh, 34390D34h, 4D1F524Dh, 39764F39h, 0BDD36EBDh
                dd 5781D657h, 6FB7D86Fh, 0DCEB37DCh, 15514415h, 7BA6DD7Bh
                dd 0F709FEF7h, 3AB68C3Ah, 0BC932FBCh, 0C0F030Ch, 0FF03FCFFh
                dd 0A9C26BA9h, 0C9BA73C9h, 0B5D96CB5h, 0B1DC6DB1h, 6D375A6Dh
                dd 45155045h, 36B98F36h, 6C771B6Ch, 0BE13ADBEh, 4ADA904Ah
                dd 0EE57B9EEh, 77A9DE77h, 0F24CBEF2h, 0FD837EFDh, 44551144h
                dd 67BDDA67h, 712C5D71h, 5454005h, 7C631F7Ch, 40501040h
                dd 69325B69h, 63B8DB63h, 28220A28h, 7C5C207h, 0C4F531C4h
                dd 22A88A22h, 9631A796h, 37F9CE37h, 0ED977AEDh, 0F649BFF6h
                dd 0B4992DB4h, 0D1A475D1h, 4390D343h, 485A1248h, 0E258BAE2h
                dd 9771E697h, 0D264B6D2h, 0C270B2C2h, 26AD8B26h, 0A5CD68A5h
                dd 5ECB955Eh, 29624B29h, 303C0C30h, 5ACE945Ah, 0DDAB76DDh
                dd 0F9867FF9h, 95F16495h, 0E65DBBE6h, 0C735F2C7h, 242D0924h
                dd 17D1C617h, 0B9D66FB9h, 1BDEC51Bh, 12948612h, 60781860h
                dd 0C330F3C3h, 0F5897CF5h, 0B35CEFB3h, 0E8D23AE8h, 73ACDF73h
                dd 35794C35h, 80A02080h, 0E59D78E5h, 0BB56EDBBh, 7D235E7Dh
                dd 0F8C63EF8h, 5F8BD45Fh, 2FE7C82Fh, 0E4DD39E4h, 21684921h
; int SM4_SBOX_T0[256]
SM4_SBOX_T0     dd 8ED55B5Bh, 0D0924242h, 4DEAA7A7h, 6FDFBFBh, 0FCCF3333h
                                        ; DATA XREF: SM4_T+E↑r
                dd 65E28787h, 0C93DF4F4h, 6BB5DEDEh, 4E165858h, 6EB4DADAh
                dd 44145050h, 0CAC10B0Bh, 8828A0A0h, 17F8EFEFh, 9C2CB0B0h
                dd 11051414h, 872BACACh, 0FB669D9Dh, 0F2986A6Ah, 0AE77D9D9h
                dd 822AA8A8h, 46BCFAFAh, 14041010h, 0CFC00F0Fh, 2A8AAAAh
                dd 54451111h, 5F134C4Ch, 0BE269898h, 6D482525h, 9E841A1Ah
                dd 1E061818h, 0FD9B6666h, 0EC9E7272h, 4A430909h, 10514141h
                dd 24F7D3D3h, 0D5934646h, 53ECBFBFh, 0F89A6262h, 927BE9E9h
                dd 0FF33CCCCh, 4555151h, 270B2C2Ch, 4F420D0Dh, 59EEB7B7h
                dd 0F3CC3F3Fh, 1CAEB2B2h, 0EA638989h, 74E79393h, 7FB1CECEh
                dd 6C1C7070h, 0DABA6A6h, 0EDCA2727h, 28082020h, 48EBA3A3h
                dd 0C1975656h, 80820202h, 0A3DC7F7Fh, 0C4965252h, 12F9EBEBh
                dd 0A174D5D5h, 0B38D3E3Eh, 0C33FFCFCh, 3EA49A9Ah, 5B461D1Dh
                dd 1B071C1Ch, 3BA59E9Eh, 0CFFF3F3h, 3FF0CFCFh, 0BF72CDCDh
                dd 4B175C5Ch, 52B8EAEAh, 8F810E0Eh, 3D586565h, 0CC3CF0F0h
                dd 7D196464h, 7EE59B9Bh, 91871616h, 734E3D3Dh, 8AAA2A2h
                dd 0C869A1A1h, 0C76AADADh, 85830606h, 7AB0CACAh, 0B570C5C5h
                dd 0F4659191h, 0B2D96B6Bh, 0A7892E2Eh, 18FBE3E3h, 47E8AFAFh
                dd 330F3C3Ch, 674A2D2Dh, 0B071C1C1h, 0E575959h, 0E99F7676h
                dd 0E135D4D4h, 661E7878h, 0B4249090h, 360E3838h, 265F7979h
                dd 0EF628D8Dh, 38596161h, 95D24747h, 2AA08A8Ah, 0B1259494h
                dd 0AA228888h, 8C7DF1F1h, 0D73BECECh, 5010404h, 0A5218484h
                dd 9879E1E1h, 9B851E1Eh, 84D75353h, 0, 5E471919h, 0B565D5Dh
                dd 0E39D7E7Eh, 9FD04F4Fh, 0BB279C9Ch, 1A534949h, 7C4D3131h
                dd 0EE36D8D8h, 0A020808h, 7BE49F9Fh, 20A28282h, 0D4C71313h
                dd 0E8CB2323h, 0E69C7A7Ah, 42E9ABABh, 43BDFEFEh, 0A2882A2Ah
                dd 9AD14B4Bh, 40410101h, 0DBC41F1Fh, 0D838E0E0h, 61B7D6D6h
                dd 2FA18E8Eh, 2BF4DFDFh, 3AF1CBCBh, 0F6CD3B3Bh, 1DFAE7E7h
                dd 0E5608585h, 41155454h, 25A38686h, 60E38383h, 16ACBABAh
                dd 295C7575h, 34A69292h, 0F7996E6Eh, 0E434D0D0h, 721A6868h
                dd 1545555h, 19AFB6B6h, 0DF914E4Eh, 0FA32C8C8h, 0F030C0C0h
                dd 21F6D7D7h, 0BC8E3232h, 75B3C6C6h, 6FE08F8Fh, 691D7474h
                dd 2EF5DBDBh, 6AE18B8Bh, 962EB8B8h, 8A800A0Ah, 0FE679999h
                dd 0E2C92B2Bh, 0E0618181h, 0C0C30303h, 8D29A4A4h, 0AF238C8Ch
                dd 7A9AEAEh, 390D3434h, 1F524D4Dh, 764F3939h, 0D36EBDBDh
                dd 81D65757h, 0B7D86F6Fh, 0EB37DCDCh, 51441515h, 0A6DD7B7Bh
                dd 9FEF7F7h, 0B68C3A3Ah, 932FBCBCh, 0F030C0Ch, 3FCFFFFh
                dd 0C26BA9A9h, 0BA73C9C9h, 0D96CB5B5h, 0DC6DB1B1h, 375A6D6Dh
                dd 15504545h, 0B98F3636h, 771B6C6Ch, 13ADBEBEh, 0DA904A4Ah
                dd 57B9EEEEh, 0A9DE7777h, 4CBEF2F2h, 837EFDFDh, 55114444h
                dd 0BDDA6767h, 2C5D7171h, 45400505h, 631F7C7Ch, 50104040h
                dd 325B6969h, 0B8DB6363h, 220A2828h, 0C5C20707h, 0F531C4C4h
                dd 0A88A2222h, 31A79696h, 0F9CE3737h, 977AEDEDh, 49BFF6F6h
                dd 992DB4B4h, 0A475D1D1h, 90D34343h, 5A124848h, 58BAE2E2h
                dd 71E69797h, 64B6D2D2h, 70B2C2C2h, 0AD8B2626h, 0CD68A5A5h
                dd 0CB955E5Eh, 624B2929h, 3C0C3030h, 0CE945A5Ah, 0AB76DDDDh
                dd 867FF9F9h, 0F1649595h, 5DBBE6E6h, 35F2C7C7h, 2D092424h
                dd 0D1C61717h, 0D66FB9B9h, 0DEC51B1Bh, 94861212h, 78186060h
                dd 30F3C3C3h, 897CF5F5h, 5CEFB3B3h, 0D23AE8E8h, 0ACDF7373h
                dd 794C3535h, 0A0208080h, 9D78E5E5h, 56EDBBBBh, 235E7D7Dh
                dd 0C63EF8F8h, 8BD45F5Fh, 0E7C82F2Fh, 0DD39E4E4h, 68492121h
