from pwn import *

def start_conn():
    return remote('localhost', 1337, ssl=True)


def get(io, key):
    io.recv(8)
    io.send(key)

    blk = b'\x00' * 0x100
    io.send(blk)

    result = io.recv(0x100)
    io.close()
    return result

