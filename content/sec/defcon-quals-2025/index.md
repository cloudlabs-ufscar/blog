+++
date = 2025-05-21T18:00:00-03:00
draft = false
title = "DEF CON Quals 2025"
description = "DEF CON Quals 2025 — writeups"
tags = ['CTF', 'reversing', 'crypto']
categories = []
featured = true
[params]
  locale = "en"
+++

More than one month has past since DEF CON Quals, but we were so exhausted by it only now we managed to put together this set of write-ups. This year, several [CTF-BR](https://ctf-br.org) affiliated teams united to form `pwn de queijo` (a pun with [pão de queijo](https://en.wikipedia.org/wiki/Cheese_bun)). Together, we managed to achieve top17, the best position achieved by a Brazilian team until now. Let's keep training to get qualified to the Finals next year :D

Unfortunately, the new Cloudlabs students did not manage to participate, since they had just joined the group. However, we had the pleasure to play with Vinicius, a long time Cloudlabs student, and Daniel and Miguel, two former students who now work at [Magalu Cloud](https://magalu.cloud).

![Cloudlabs alumni](./photos/Hackaflag-46.jpg)

We are grateful to [Flipside](https://flipside.com.br) for providing such a nice space for us to gather together.

Now let's get to the write-ups.

## rainbow mountain

We were given the [rbm](./rbm/rbm) binary.

Since the binary is statically linked, and since it had strings referencing `GCC: (Debian 12.2.0-14) 12.2.0`, which is a version of gcc shipped with Debian bookworm, we started by generating FLIRT signatures for libc and libstdc++ from that distro, and loaded them into IDA Pro.

Then, we spent a couple of hours reversing the main program, since it had a lot of C++ indirection going on and we thought some important behavior could be hidden there. However, it turns out the program simply called 0x4E8440 (which we named `fill_func_arr`) to load a big array of functions, then asked the user which of these functions they wanted to call, and finally asked for some base64 encoded data to pass as an argument to the chosen function. Lesson learned: start thinking simple; only if that does not work, carry out a deep analysis.

We noticed the first two functions of the array (0x404450 and 0x404780) did the same thing, only dimensions of the buffers were different. They copied the provided string into a grid (9x8 or 7x5, respectively) called `arr` in boustrophedonic order (i.e. consecutive rows alternated between left-to-right and right-to-left). In the stack, just after `arr`, there was a small buffer called `target`. After copying the provided string to `arr`, the function checked if `target` contained some `wanted` string.

In short, we needed to find which function had `arr` dimensions shorter than the grid size. Then, it would be possible to overflow `arr` and overwrite `target` with the desired string.

Since there were a lot of functions, we needed to automate the search. We used IDA Pro menu `File -> Produce File -> Create C File` to decompile the entire program into [rbm.c](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/rbm/rbm.c).

We noticed one of the functions we still didn't manually analyze had the following structure:

```c
  _BYTE v27[64]; // [rsp+60h] [rbp-60h] BYREF
  __int64 v28; // [rsp+A0h] [rbp-20h]
  __int64 v29; // [rsp+A8h] [rbp-18h]
  __int64 v30; // [rsp+B0h] [rbp-10h]
  __int64 v31; // [rsp+B8h] [rbp-8h]

  v31 = a1;
  v30 = 9;
  v29 = 7;
  v28 = 0;
```

where `v27` is `arr`, `v28` is `target`, and `v30`x`v29` is the grid size. Then, we wrote a Python script to look for a function allowing to overflow `arr` at least by 8 bytes (size of `target`). 

```python
import re
import sys

with open('rbm.c') as f:
    data = f.read()

for m in re.finditer(r'_BYTE v27\[(\d+)\];(.*?)  v30 = (\d+);\n  v29 = (\d+);\n', data, re.DOTALL):
    arr_size, garbage, len1, len2 = m.groups()
    arr_size = int(arr_size)
    garbage = len(garbage)
    len1 = int(len1)
    len2 = int(len2)
    assert garbage == 194
    if len1 * len2 >= arr_size + 8:
        print('line', data[:m.start()].count('\n'))
        print(len1, len2, arr_size)
        sys.exit(1337)
```

Unfortunately, there was no such function.

We got back at the decompiled code and realized not all of the functions from the big array followed the template we were looking for.

We spotted the first function we found (0x405730) which was different from the template we previously analyzed. It simply copied the input string to `arr`. It was much simpler since it did not reorder the string contents. The following excerpt was extracted from that function:

```c
  _BYTE v12[80]; // [rsp+28h] [rbp-68h] BYREF
  __int64 v13; // [rsp+78h] [rbp-18h]
  __int64 v14; // [rsp+80h] [rbp-10h]
  __int64 v15; // [rsp+88h] [rbp-8h]

  v15 = a1;
  v14 = 79;
  v13 = 0;
  v11 = 0x5A43474C43613378LL;
  v9 = string_len_(a1);
  v8 = 83;
```

where `v12` is `arr`, `v13` is `target`, `v11` is `wanted`, and `v8` is the maximum amount of bytes copied from the input string to `arr`.

Notice the function above allows to overflow `arr` by 3 bytes, but that is not enough to replace `target` with the `wanted` value. Once again, we need to find a function allowing to overflow at least 8 bytes.

Now we complement our Python script with a regex for the newly discovered function template.

```python
for m in re.finditer(r'_BYTE v12\[(\d+)\];(.*?)  v8 = (\d+);', data, re.DOTALL):
    arr_size, garbage, can_copy = m.groups()
    arr_size = int(arr_size)
    #garbage = len(garbage)
    can_copy = int(can_copy)
    if can_copy >= arr_size + 8:
        print('line', data[:m.start()].count('\n'))
        print(can_copy, arr_size)
        sys.exit(1337)
```

The search finally returned something interesting:

```text
line 153797
72 64
```

Around that line in [rbm.c](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/rbm/rbm.c), we had the following function:

```c
_BOOL8 __fastcall sub_4B82B0(__int64 a1)
{
  __int64 v1; // rax
  _QWORD *v2; // rax
  __int64 v3; // rax
  _QWORD *v4; // rax
  __int64 v5; // rax
  __int64 v7; // [rsp+8h] [rbp-88h]
  __int64 v8; // [rsp+10h] [rbp-80h] BYREF
  __int64 v9; // [rsp+18h] [rbp-78h] BYREF
  __int64 v10; // [rsp+20h] [rbp-70h]
  __int64 v11; // [rsp+28h] [rbp-68h]
  _BYTE v12[64]; // [rsp+30h] [rbp-60h] BYREF
  __int64 v13; // [rsp+70h] [rbp-20h]
  __int64 v14; // [rsp+78h] [rbp-18h]
  __int64 v15; // [rsp+80h] [rbp-10h]

  v15 = a1;
  if ( (sub_4042E0(a1) & 1) != 0 )
  {
    v14 = 58;
    v13 = 0;
    v11 = 0x3447784339354946LL;
    v9 = string_len_(v15);
    v8 = 72;
    v10 = *min(&v9, &v8);
    v7 = sub_4F5810((__int64)v12);
    v1 = sub_4F52B0(v15);
    j_ifunc_5CC6D0(v7, v1, v10);
    v2 = operator_write_stream(std_cerr, (__int64)"target: ");
    unknown_libname_550(v2, sub_4F50B0);
    v3 = std::ostream::_M_insert<unsigned long>();
    operator_write(v3, std::endl<char,std::char_traits<char>>);
    v4 = operator_write_stream(std_cerr, (__int64)"wanted: ");
    unknown_libname_550(v4, sub_4F50B0);
    v5 = std::ostream::_M_insert<unsigned long>();
    operator_write(v5, std::endl<char,std::char_traits<char>>);
    return v13 == v11;
  }
  else
  {
    return 0;
  }
}
```

It did not follow exactly our template, since it checked the input string with `sub_4042E0` before copying it to `arr`. We analyzed `sub_4042E0` and discovered it checked if the string was a palindrome.

So far so good, now we have everything we need to set up an overflow.

We got back to `fill_func_array` to see `sub_4B82B0` is in position `1576` of the function array.

We fired ipython to mount a palindrome input ending with the `wanted` value and to encode it to base64.

```python
In [1]: from pwn import *

In [2]: wanted = p64(0x3447784339354946)

In [3]: wanted
Out[3]: b'FI59CxG4'

In [4]: base64.b64encode(wanted[::-1] + (64-8)*b'A' + wanted)
Out[4]: b'NEd4Qzk1SUZBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUZJNTlDeEc0'
```

Finally, we tested it locally and it worked!

```text
$ ./rbm
rainbow mountain
function index:
1576
picked 7fffc58e0560
base64'd input: NEd4Qzk1SUZBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUZJNTlDeEc0
decoded 72 bytes
target: 3447784339354946
wanted: 3447784339354946
correct!
the flag is no flag configured! contact orga
```

And that's it. No point in showing the flag we received from the server, since they provided a different random flag for each team (as part of their infrastructure for *flag sharing prevention*).

I'd like to thank André Slepetys for the fruitful discussions during the entire reversing process.

## dialects

For this challenge, we were given the [ctf](./dialects/ctf) binary.

The solution we will now discuss was a collaboration with Bruno, the Relentless Mage from [Ganesh](https://ganesh.icmc.usp.br). I was responsible for the reversing part, and Bruno was responsible for the crypto and for writing the solver.

![The (Relentless) Crypto Mage](./photos/IMG_5008.jpg)

As usual, since [ctf](./dialects/ctf) is a static binary, we start by trying to create and load adequate FLIRT signatures. The binary contains the following strings which give hints about the compiler and linked libs:

```text
OpenSSL 3.6.0-dev
compiler: /opt/cross/bin/x86_64-linux-musl-gcc -pthread -m64 -Os -msse4 -Wa,--noexecstack -Wall -O3 --static -enable-sm4 -enable-sm2 -enable-sm3 -enable-weak-ssl-ciphers -enable-hw -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -I/opt/cross/include
GCC: (GNU) 9.4.0
```

After some web search, we find [a toolchain builder for musl](https://github.com/richfelker/musl-cross-make/tree/6f3701d08137496d5aac479e3a3977b5ae993c1f) which uses the same GCC version. Unfortunately, there are no prebuilt binary packages, so we build it.

The OpenSSL version is 3.6.0-dev, therefore our best guess is to build the [latest revision from their git](https://github.com/openssl/openssl/tree/172076029c0bbb188e321f5832f6a15971834e90) at the time of the CTF. 

After some trial and error, we arrive at the following configure options which produce a lib with almost the same `compiler` string as we observed in the binary: `./Configure --cross-compile-prefix=x86_64-linux-musl- -no-shared -enable-sm4 -enable-sm2 -enable-sm3 -enable-weak-ssl-ciphers -enable-hw -no-pic`. Manually replacing `-Wall -O3` with `-Wall -O3 --static` and `-pthread -m64` with `-pthread -m64 -Os -msse4` in `configdata.pm` gave the final touch.

Unfortunately, that effort did not pay much. FLIRT signatures generated from musl's `libc.a` matched well with the binary, but the ones from `libssl.a` did not. Curiously, signatures generated from `libcrypto.a` (also built from OpenSSL sources) did match well, but they did not help much with the analysis.

Fortunately, OpenSSL binaries retain a lot of strings referencing function names, source code file names and line numbers, displayed on assertion failures and on other errors. For example, the `SSL_write` function contains the following call:

```c
nullsub_25("ssl/ssl_lib.c", 2673, "SSL_write");
```

Therefore, we started analyzing from the `main` function and manually renamed functions (and set argument types) every time we found an OpenSSL function.

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  struct SSL_CTX *ssl_ctx; // rbp
  struct SSL *ssl; // rbp
  int result; // eax

  signal(SIGPIPE, 1);
  ssl_ctx = (struct SSL_CTX *)create_ssl_ctx();
  load_cert_key(ssl_ctx);
  alarm(10);
  ssl = SSL_new(ssl_ctx);
  SSL_set_rfd(ssl, 0);
  SSL_set_wfd(ssl, 1);
  if ( SSL_accept(ssl) > 0 )
    return main_loop(ssl);
  show_logs(10937152);
  return result;
}

__int64 __fastcall main_loop(struct SSL *ssl)
{
  struct EVP_CIPHER_CTX *cipher_ctx; // r12
  __int64 memzero_size; // rcx MAPDST
  _DWORD *memzero_p; // rdi MAPDST
  __int64 result; // rax
  struct EVP_CIPHER *evp_cipher; // rax
  EVP_MD *evp_md; // rax
  void *sha512; // rax
  unsigned int fd; // eax
  __int64 exitstatus; // rdi
  unsigned __int8 filename[256]; // [rsp-100h] [rbp-310h] BYREF
  void *can_call_cmd1; // [rsp+0h] [rbp-210h]
  struct EVP_MD_CTX *hash_ctx; // [rsp+8h] [rbp-208h] MAPDST
  unsigned __int8 *buf3p; // [rsp+10h] [rbp-200h]
  unsigned __int8 *buf2p; // [rsp+18h] [rbp-1F8h]
  int cmd_1_or_2; // [rsp+28h] [rbp-1E8h] BYREF
  int len; // [rsp+2Ch] [rbp-1E4h] BYREF
  unsigned __int8 key[16]; // [rsp+30h] [rbp-1E0h] BYREF
  uint8_t nonce[16]; // [rsp+40h] [rbp-1D0h] BYREF
  unsigned __int8 buf4[16]; // [rsp+50h] [rbp-1C0h] BYREF
  unsigned __int8 iv[32]; // [rsp+60h] [rbp-1B0h] BYREF
  _BYTE buf2[32]; // [rsp+80h] [rbp-190h] BYREF
  _BYTE buf3[32]; // [rsp+A0h] [rbp-170h] BYREF
  unsigned __int8 buf1[304]; // [rsp+E0h] [rbp-130h] BYREF

  cipher_ctx = EVP_CIPHER_CTX_new();
  hash_ctx = EVP_MD_CTX_new();
  memzero_size = 8;
  memzero_p = iv;
  while ( memzero_size )
  {
    *memzero_p++ = 0;
    --memzero_size;
  }
  cmd_1_or_2 = 0;
  *(_OWORD *)key = 0;
  result = getrandom(key, 8u, 0);               // server chooses first 8 bytes of key
  if ( result == 8 )
  {
    SSL_write(ssl, key, 8);                     // send the server part of the key
    SSL_read(ssl, &key[8], 8);                  // client chooses last 8 bytes of key
    evp_cipher = EVP_sm4_ctr();
    EVP_EncryptInit(cipher_ctx, evp_cipher, key, iv);
    evp_md = EVP_sm3();
    EVP_DigestInit(hash_ctx, evp_md, 0);
    LODWORD(can_call_cmd1) = 0;
    while ( SSL_read(ssl, buf1, 256) == 4 )
    {
      EVP_EncryptUpdate(cipher_ctx, (unsigned __int8 *)&cmd_1_or_2, &len, buf1, 4);
      buf2p = buf2;
      buf3p = buf3;
      if ( cmd_1_or_2 == 1 )
      {
        if ( !(_DWORD)can_call_cmd1 )
          break;
        getrandom(buf4, 16u, 0);                // buf4 is nonce
        SSL_write(ssl, buf4, 16);
        SSL_read(ssl, buf2p, 16);               // buf2 is encrypted clientdata
        EVP_EncryptUpdate(cipher_ctx, buf3p, &len, buf2p, 16);// buf3 is decrypted clientdata
        *(_OWORD *)&buf3[16] = *(_OWORD *)buf4; // buf3 is (decrypted clientdata || nonce)
        sha512 = compute_sha512(buf3p, 32, 0);
        if ( (unsigned int)strcmp(sha512, &expected_sha512) )// expected_sha512 is {0x8D, 0x36, 0}
          break;
        len = 256;
        SSL_read(ssl, buf1, 256);               // buf1 is encrypted filename
        EVP_EncryptUpdate(cipher_ctx, filename, &len, buf1, 256);
        fd = open((const char *)filename, 0);
        len = read(fd, buf1, 256);              // buf1 is file contents
        SSL_write(ssl, buf1, len);
      }
      else
      {
        if ( cmd_1_or_2 != 2 )
          break;
        memzero_p = buf3p;
        for ( memzero_size = 16; memzero_size; --memzero_size )
          *memzero_p++ = 0;
        can_call_cmd1 = nonce;                  // ugly stack reuse by the compiler
        getrandom(nonce, 16u, 0);
        SSL_write(ssl, can_call_cmd1, 16);      // SSL_write(ssl, nonce, 16);
        *(_OWORD *)buf4 = 0;
        SSL_read(ssl, buf4, 16);                // buf4 is encrypted clientdata
        *(_OWORD *)&buf2[16] = *(_OWORD *)nonce;
        EVP_EncryptUpdate(cipher_ctx, buf2p, &len, buf4, 16);// buf2 is (decrypted clientdata || nonce)
        EVP_DigestUpdate(hash_ctx, buf2p, 32u);
        EVP_DigestFinal_ex(hash_ctx, buf3p, 0); // buf3 is sm3(decrypted clientdata || nonce)
        if ( buf3[2] | (unsigned __int8)(buf3[1] | buf3[0]) )// first 3 bytes of the sm3 hash must be zero
        {
          exitstatus = 2;
          goto do_exit;
        }
      }
      LODWORD(can_call_cmd1) = 1;
    }
    exitstatus = 0;
do_exit:
    exit(exitstatus);
  }
  return result;
}
```

Functions `EVP_sm4_ctr` and `EVP_sm3` above were a little tricky to identify. By identifying other OpenSSL functions called by `main_loop`, we knew these yet unknown functions needed to return an `EVP_CIPHER*` and an `EVP_MD*`, respectively. Loading these structs from OpenSSL header files into IDA Pro, then following the values returned by the unknown functions, we found:

```text
.rodata:0000000000705C60 stru_705C60     EVP_CIPHER <473h, 1, 10h, 10h, 5, 1, offset sub_4A3506, \
.rodata:0000000000705C60                             offset sub_4A36EF, 0, 90h, 0, 0, 0, 0, 0, 0, 0, 0, <0>,\
.rodata:0000000000705C60                             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, \
.rodata:0000000000705C60                             0>

.rodata:000000000072DBA0 stru_72DBA0     EVP_MD <477h, 478h, 20h, 0, 1, offset sub_4DDB1E, offset sub_4DDAF7, \
.rodata:000000000072DBA0                         offset sub_4DDAE2, 0, 0, 40h, 0, 0, 0, 0, 0, 0, <0>, 0, 0, 0, \
.rodata:000000000072DBA0                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>
```

The first attribute of each struct is called `nid`. Looking for their values (converted to decimal) in OpenSSL source code, we identified 1139 as [NID_sm4_ctr](https://github.com/openssl/openssl/blob/a0d1af6574ae6a0e3872d20ff302a78793c05a85/include/openssl/obj_mac.h#L5399) and 1143 as [NID_sm3](https://github.com/openssl/openssl/blob/a0d1af6574ae6a0e3872d20ff302a78793c05a85/include/openssl/obj_mac.h#L1237).

Looking at Wikipedia, we found [SM4](https://en.wikipedia.org/wiki/SM4_(cipher)) was indeed a block cipher, and [SM3](https://en.wikipedia.org/wiki/SM3_(hash_function)) was indeed a hash function. Both were published by the Chinese National Cryptography Administration.

Now we knew what to do:

1. Connect to it via TLS. However, the binary is speaking TLS via stdin/stdout instead of a socket. We wrote a [run.sh](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/dialects/run.sh) script to wrap it with `socat` so that we could connect to it using ordinary pwntools stuff.

2. Server chooses first 8 bytes of a key, we choose the last 8 bytes. Use that key to encrypt all the next messages with SM4 in CTR mode.

3. Send command 2, then find a text such that `sm3(text || value given by server)` begins with three 0 bytes.

4. Send command 1, then find a text such that `sha512(text || value given by server)` begins with `{0x8D, 0x36, 0}`.

5. Send the name of the file we want to read (`./flag.txt`).

However, things were not so simple. We compared some values produced by SM3 and SM4 from standard OpenSSL and values produced by the ctf binary, and realized they were different. Nautilus Institute changed the algorithms somehow.

First idea was to visually compare the decompiled algorithms with OpenSSL source code. We immediately spot some differences:

```c
/* SM4 cipher */
static inline uint32_t SM4_key_sub(uint32_t X)
{
    uint32_t t = SM4_T_non_lin_sub(X);

    // return t ^ rotl(t, 13) ^ rotl(t, 23); // Original Chinese
    return t ^ rotl(t, 12) ^ rotl(t, 24);    // Nautilus Institute
}

/* SM3 hash */

// Original Chinese
#define SM3_A 0x7380166fUL
#define SM3_B 0x4914b2b9UL
#define SM3_C 0x172442d7UL
#define SM3_D 0xda8a0600UL
#define SM3_E 0xa96f30bcUL
#define SM3_F 0x163138aaUL
#define SM3_G 0xe38dee4dUL
#define SM3_H 0xb0fb0e4eUL

// Nautilus Institute
a1[0] = 0x4914B2B9A96F30BCLL;  // SM3_A is different
a1[1] = 0xDA8A0600172442D7LL;
a1[2] = 0x163138AA7380166FLL;  // SM3_E is different
a1[3] = 0xB0FB0E4EE38DEE4DLL;
```

However, these were not the only changes. We tried to patch OpenSSL with the changes above but it was not enough to produce the same outputs.

Then, [Mercês](https://mentebinaria.com.br) suggested a [ptrace-based wrapper](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/merces) approach to call the ctf binary functions externally, which was quite elegant, but wasn't performant enough to conclude the brute force before the server timeout.

Since SM4 was being used in CTR mode, it was easy to modify the provided binary to produce a keystream for a given key, which we could then XOR with anything we wanted to encrypt or decrypt. Bruno patched the binary as follows:

```text
; original
.text:00000000004002FF                 lea     rsi, [rbp+key+8]
.text:0000000000400306                 mov     edx, 8
.text:000000000040030B                 mov     rdi, rbx
.text:000000000040030E                 call    SSL_read
; patch to read the entire key from the client
.text:00000000004002FF                 lea     rsi, [rbp+key]
.text:0000000000400306                 mov     edx, 16
.text:000000000040030B                 mov     rdi, rbx
.text:000000000040030E                 call    SSL_read

; original
.text:000000000040035B                 call    SSL_read
.text:0000000000400360                 cmp     eax, 4
.text:0000000000400363                 jnz     loc_4005AD
; patch to allow reading more than 4 bytes (to pass to EVP_EncryptUpdate)
.text:000000000040035B                 call    SSL_read
.text:0000000000400360                 cmp     eax, 4
.text:0000000000400363                 nop
.text:0000000000400364                 nop
.text:0000000000400365                 nop
.text:0000000000400366                 nop
.text:0000000000400367                 nop
.text:0000000000400368                 nop

; original
.text:000000000040037A                 mov     r8d, 4
.text:0000000000400380                 mov     rdx, r15
.text:0000000000400383                 mov     rdi, r12
.text:0000000000400386                 lea     r14, [rbp+buf4]
.text:000000000040038D                 call    EVP_EncryptUpdate
; patch to encrypt 0x100 bytes (instead of 4 bytes)
.text:000000000040037A                 mov     r8d, 100h
.text:0000000000400380                 mov     rdx, r15
.text:0000000000400383                 mov     rdi, r12
.text:0000000000400386                 lea     r14, [rbp+buf4]
.text:000000000040038D                 call    EVP_EncryptUpdate

; original
.text:0000000000400392                 mov     eax, [rbp+cmd_1_or_2]
.text:0000000000400398                 lea     rcx, [rbp+buf2]
.text:000000000040039F                 mov     [rbp+buf2p], rcx
; patch to send EVP_EncryptUpdate results back to the client
.text:0000000000400392                 mov     edx, 100h
.text:0000000000400397                 lea     rsi, [rbp+cmd_1_or_2]
.text:000000000040039E                 mov     rdi, rbx
.text:00000000004003A1                 call    SSL_write
```

The resulting binary is available as [ctf-patch](./dialects/ctf-patch), and it is called by [get_vals_patch.py](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/dialects/get_vals_patch.py) to generate a keystream (by encrypting `b'\x00' * 0x100`).

A similar approach would be doable for SM3, but the patch would be more complex. Executing the process several times to carry out the brute force would result in too much overhead and would not conclude before the timeout. Therefore, we would need to insert the entire brute forcing loop inside the binary via patching.

However, while Bruno was working in this, I isolated the functions responsible for implementing SM3 and SM4 and converted them from IDA Pro syntax to NASM (this is mostly about removing the `ptr` keyword). The results are in [libchina.asm](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/dialects/libchina.asm).

Please note the original binary is not PIE, therefore we need to pass `-no-pie` to gcc when linking that lib to a program, otherwise we will get some error like:

```text
/usr/bin/ld: libchina.o: relocation R_X86_64_32S against `.rodata' can not be used when making a PIE object; recompile with -fPIE
/usr/bin/ld: failed to set dynamic section sizes: bad value
```

In the end, I provided Bruno with libchina and a [small example](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/dialects/test.c) on how to use it and he finished [solve.py](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/dialects/solve.py). He integrated only SM3 from libchina, since SM4-CTR using the patched binary was already working OK.

Finally, everything was working locally, but in the server the challenge was wrapped by Nautilus Institute's *flag sharing prevention* infrastructure. It asked for our Ticket in plaintext, before TLS was started. Thus, we needed to study pwntools source code to figure out how to convert a plain socket to a TLS socket during an already established connection:

```python
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
io.sock = context.wrap_socket(io.sock)
```

You can test the final solver from the [repo](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/dialects) as follows:

```text
$ make
nasm -f elf64 libchina.asm -o libchina.o
gcc -no-pie test.c libchina.o -o test
gcc -Ofast -c sha512.c -o libsha.o
gcc -no-pie -Ofast -fopenmp brute_hash.c libchina.o libsha.o -o brute_hash
openssl req -newkey rsa:2048 -nodes -keyout example.com.key -x509 -subj '/CN=lol/' -days 365 -out example.com.crt
.....+......+....+.........+..+++++++++++++++++++++++++++++++++++++++*.+.....+.+............+++++++++++++++++++++++++++++++++++++++*...+.........+...++++++
..........+...+.+...+..+.+........+++++++++++++++++++++++++++++++++++++++*..+...+.+.....+......+...+....+......+.....+......+...............+++++++++++++++++++++++++++++++++++++++*.+......+....+.....+......+......++++++
-----
$ ./run.sh &
[1] 50036
$ ./run_patch.sh &
[2] 50064
$ python solve.py
[+] Opening connection to localhost on port 1337: Done
[+] Starting local process './brute_hash': pid 49535
[+] Starting local process './brute_hash': pid 49537
[+] Opening connection to localhost on port 12345: Done
Their: 9bfa65d891a54ffc
0xfc4fa591d865fa9b
Final: 9bfa65d891a54ffc3f3f3f3f3f3f3f3f
[*] Closed connection to localhost port 1337
Ks: 09fd82d0122d4926b20b1b05fb425c82cc3204207ea0cbfa3926a2db855ff3c1a8d0128ad879eff1bebb69be403aaf135e9568ae2eec176010c51c710238cc3d0975127729e28724c5a4d8e44b0f9d4cd82e0d82ee6b0f3d758dc10db7eeea7c0b2db65238d9e3f6eabfc68dbdc1044c3a02c52e27970b0e76d6e8252528d7601158ac3e3d40ffb22bfe0e414472b40cda9f047be3ee701a48ede87ea9aeea6c7814ab51b968e94312828fb922962ee05d213be7159267f53da901966ffea74cd9d145ed0c04417e4bd4ae4ff2a2aeab828751137a7c970623f3829760adbab4327e1e6107a2609b9df7bec21266906a2e692f490df2b4317404745ebefbc480
Got nonce: 92d6ec5452d19d468836f536758daa9f
Pay:  0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x20 0x92 0xd6 0xec 0x54 0x52 0xd1 0x9d 0x46 0x88 0x36 0xf5 0x36 0x75 0x8d 0xaa 0x9f
Final node: 20202000862020fd202020207a20202092d6ec5452d19d468836f536758daa9f
Mine: 20202000862020fd202020207a202020
Got nonce: 21fcd3bda5c642c3bad4bcad3da01d9a
Nonce final: 303030387f303076303030300830303021fcd3bda5c642c3bad4bcad3da01d9a
Mine: 303030387f3030763030303008303030
11
[*] Switching to interactive mode
defcon{test_flag}
```