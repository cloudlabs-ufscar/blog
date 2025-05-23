from pwn import *
import get_vals_patch
import get_hash1
import sha512_brute

def xor(sa, sb):
    return bytes(a^b for a, b in zip(sa, sb))

io_p1 = get_vals_patch.start_conn()
io_h1 = get_hash1.start_conn()
io_h2 = sha512_brute.start_conn()

targ_fpath = b'./flag.txt\x00'

isremote = False 
if isremote:
    io = remote('dialects-7qpig3ofzdmyi.shellweplayaga.me', 4433)          
    io.sendlineafter(b'Ticket please: ', b'ticket{ZombieCute3522n25:VeXTKhB0jNg5ts18cB5Ry2hi4ZRIoiU4cZ_7n_Ds3_7TJVzE}')                               
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)                         
    io.sock = context.wrap_socket(io.sock)
else:
    io = remote('localhost', 12345, ssl=True)

ini_key = io.recv(8)
my_part_key = b'?' * 8
key = ini_key + my_part_key

print('Their:', ini_key.hex())
print(hex(u64(ini_key)))
print('Final:', key.hex())

io.send(my_part_key)

ks = get_vals_patch.get(io_p1, key)
print('Ks:', ks.hex())
cmd2 = xor(ks[:4], p32(2))
ks = ks[4:]

io.send(cmd2)

nonce = io.recv(16)
print('Got nonce:', nonce.hex())

final_node = get_hash1.get(io_h1, b' ' * 16 + nonce)
print('Final node:', final_node.hex())

assert final_node[16:] == nonce 

mine = final_node[:16]
print('Mine:', mine.hex())

mine = xor(mine, ks[:16])
ks = ks[16:]
io.send(mine)

cmd1 = xor(p32(1), ks[:4])
ks = ks[4:]

io.send(cmd1)

nonce = io.recv(16)
print('Got nonce:', nonce.hex())

mine = b'0' * 16 
nonce_final = sha512_brute.get(io_h2, mine + nonce)

print('Nonce final:', nonce_final.hex())
assert nonce_final[16:] == nonce 

mine = nonce_final[:16]
print('Mine:', mine.hex())

mine = xor(mine, ks[:16])
ks = ks[16:]

io.send(mine)

#dt = cyclic(256)
dt = targ_fpath
dt = xor(dt, ks)

print(len(dt))
io.send(dt)

io.interactive()

