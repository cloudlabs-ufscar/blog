from iced_x86 import Decoder, Mnemonic
from find_offsets import follow_jumps_until

RIP = 0
def get_bits(CODE, offset):
    IP = 0
    
    for i in range(64):
        instr = follow_jumps_until(CODE, offset, [Mnemonic.TEST, Mnemonic.CMP], IP)
        
        
        if instr.mnemonic == Mnemonic.CMP:
            yield instr.immediate(1)
        elif instr.mnemonic == Mnemonic.TEST:
            yield 0
        else:
            yield 'X'
        
        
        if i == 63:
            return
            
        instr = follow_jumps_until(CODE, offset, Mnemonic.CALL, IP)
        offset = instr.near_branch_target - IP

def find_weird_string(FIXED_JUMPCUT_CHECK_FP, offsets):
    with open(FIXED_JUMPCUT_CHECK_FP, "rb") as file:
        CODE = file.read()
    finals = []
    
    for start in offsets:
        bits = get_bits(CODE, start)
        lbits = []
        for i, bit in enumerate(bits):
            #print(i, bit)
            lbits.append(bit)
            
        final = "".join(map(str,map(int, lbits)))[::-1]
        final = int(final, 2)
        finals.append(final)
    print("\n".join(map(hex, finals)))
    
    return finals

if __name__ == "__main__":
    
    FIXED_JUMPCUT_CHECK_FP = "./FIXED_JUMPCUT_CHECK.bin"
    offsets = [0x568d7, 0xc64ec, 0x9ef02, 0x9bd93]
    
    find_weird_string(FIXED_JUMPCUT_CHECK_FP, offsets)
