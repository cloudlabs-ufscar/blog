from pwn import *

HOST = "isitdata.chals.damctf.xyz"
PORT = 39531

commands = [
    "4",   # f
    "6",   # i
    "10",  # im
    "6",   # ip
    "5",   # io
    "5",   # in
    "7",   # ina
    # --- code adds a g here automatically ---
    "7",   # inaga
    "10",  # inagam
    "5",   # inagal
    "7",   # inagala
    "9",   # inagalaz
    "5",   # inagalay
    "5",   # inagalax
    "9",   # inagalaxz
    "5",   # inagalaxy
    "4",   # inagalaxyf
    "7",   # inagalaxyfa
    "15",  # inagalaxyfar
    "4",   # inagalaxyfarf
    "7",   # inagalaxyfarfa
    "15",  # inagalaxyfarfar
    "7",   # inagalaxyfarfara
    "9",   # inagalaxyfarfaraz
    "5",   # inagalaxyfarfaray
    "5",   # inagalaxyfarfarax
    "5",   # inagalaxyfarfaraw
    "7",   # inagalaxyfarfarawa
    "9",   # inagalaxyfarfarawaz
    "5"    # inagalaxyfarfaraway
]

io = remote(HOST, PORT)

for i, cmd in enumerate(commands):
    io.recvuntil(b"> ")
    log.info(f"({i+1}): {cmd}")
    io.sendline(cmd.encode())

final_output = io.recvall(timeout=5)
log.success(f"\n{final_output}")

io.close()