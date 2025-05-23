from pwn import *

def start_conn():
    #return process('./ctf_patch_hash')
    p = process('./brute_hash')
    p.sendlineafter(b'Algo: \n', b'sm3')
    p.recvuntil(b'Buffer: \n')
    return p 

def get(io, nonce_todo):
    pay = ' '.join(map(hex, nonce_todo))
    print('Pay: ', pay)
    io.sendline(pay.encode())

    io.recvuntil(b':')
    data = bytes.fromhex(io.recvline().decode().strip())

    if len(data) == 0:
        print('Hash not found')
        exit(1)
    assert len(data) == 32
    return data

