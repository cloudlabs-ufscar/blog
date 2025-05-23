from hashlib import sha512
from pwn import *

'''
def get(entire_nonce):
    nonce =bytearray(entire_nonce)
    for i in range(2**30):
        nonce[3] = i&0xff 
        nonce[9] = (i>>8)&0xff 
        nonce[1] = (i>>16) & 0xff 
        nonce[14] = (i>>24) & 0xff

        h = sha512(nonce).digest()
        if h[0] == 0x8d and h[1] == 0x36 and h[2] == 0:
            return nonce 

    print('sha512 not found')
    exit(1) 
'''

def start_conn():
    p = process('./brute_hash')
    p.sendlineafter(b'Algo: \n', b'sha')
    p.recvuntil(b'Buffer: \n')

    return p 

def get(io, entire_nonce):
    io.sendline(' '.join(map(hex, entire_nonce)).encode())

    io.recvuntil(b':')
    data = bytes.fromhex(io.recvline().decode().strip())
    assert len(data) == 32

    return data

