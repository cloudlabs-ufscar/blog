def misterious(rcx, edx):
 return (((((rcx << 7) & 0xffffffff) | ((rcx & 0xffffffff) >> 0x19)) ^ edx) ^ (rcx >> 32))

def for8bytes(start, values):
 #start = 0x4847464544434241
 tmp = start
 for v in values:
  tmp = ((tmp & 0xffffffff) << 32) | misterious(tmp, v)
 return tmp

def reverse(values):
    def wrapper(last):
        current = last
        for v in reversed(values):
                
            low = current & 0xffffffff
            high = current >> 0x20
            
            shenanigan = (((high << 7) & 0xffffffff) | ((high & 0xffffffff) >> 0x19))
            
            
            prevHigh = low ^ shenanigan ^ v 
            prevLow = high
            current = prevHigh << 0x20 | prevLow
            print(hex(current))
        return current
    return wrapper

# start with a number
# new number is {lowest bits of previos number, () xor highest bits }
from magic import values_from_magic

def solve(magic, weirds):
    #values = values_from_magic(0xEFB1957A03BAECF7, 0x8C982983781BCDB6)
    values = values_from_magic(magic[0], magic[1])
    solved = list(map(reverse(values), weirds))
    for s in solved:
        print(f'0x{for8bytes(s, values):8X}')
    solved_content = b"".join(map(lambda x: x.to_bytes(8, 'little').rjust(8), solved))
    #with open("license.bin", "ab") as file:
    #    file.write(solved_content)
        
    return solved_content

if __name__ == "__main__":
    print(solve([0xEFB1957A03BAECF7, 0x8C982983781BCDB6], [0xfabbd91f04381f89, 0xd13f557d1b36e7cc, 0x501aeba922f2c44c, 0x857a1bea6419ce73]))
