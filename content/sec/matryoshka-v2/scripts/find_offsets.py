from iced_x86 import *

def follow_jumps_until(CODE, offset, mnemonics, IP):
    if type(mnemonics) != list:
        mnemonics = [mnemonics]
    decoder = Decoder(64, CODE[offset:], ip=IP + offset)
    
    instr = decoder.decode()
    while instr.mnemonic != Mnemonic.JMP and instr.mnemonic not in mnemonics:
        instr = decoder.decode()
    
    
    if instr.mnemonic == Mnemonic.JMP:
        offset = instr.near_branch_target - IP
        return follow_jumps_until(CODE, offset, mnemonics, IP)
    
    return instr

def follow_jumps_after_jump(CODE, jmp, mnemonics, IP):
    offset = jmp.near_branch_target - IP
    return follow_jumps_until(CODE, offset, mnemonics, IP)

def walk_one_and_jmp(CODE, target, IP):
    decoder = Decoder(64, CODE[target - IP:], ip=target)
    
    while(instr:=decoder.decode()).mnemonic != Mnemonic.JMP:
        continue
    
    return instr

def find_offsets(FIXED_JUMPCUT_FP):
    
    with open(FIXED_JUMPCUT_FP, "rb") as file:
        CODE = file.read()
    IP = 0x0
    je = follow_jumps_until(CODE, 0, Mnemonic.JE, IP)
    je2 = follow_jumps_after_jump(CODE, je, Mnemonic.JE, IP)
    jge = follow_jumps_after_jump(CODE, je2, Mnemonic.JGE, IP)
    call1 = follow_jumps_after_jump(CODE, jge, Mnemonic.CALL, IP)
    call2 = follow_jumps_until(CODE, call1.next_ip - IP, Mnemonic.CALL, IP)
    call3 = follow_jumps_until(CODE, call2.next_ip - IP, Mnemonic.CALL, IP)
    call4 = follow_jumps_until(CODE, call3.next_ip - IP, Mnemonic.CALL, IP)
    offset1 = walk_one_and_jmp(CODE, call1.near_branch_target, IP).near_branch_target - IP
    offset2 = walk_one_and_jmp(CODE, call2.near_branch_target, IP).near_branch_target - IP
    offset3 = walk_one_and_jmp(CODE, call3.near_branch_target, IP).near_branch_target - IP
    offset4 = walk_one_and_jmp(CODE, call4.near_branch_target, IP).near_branch_target - IP
    print(hex(offset1))
    print(hex(offset2))
    print(hex(offset3))
    print(hex(offset4))
    
    return [offset1, offset2, offset3, offset4]

if __name__ == "__main__":
    FIXED_JUMPCUT_FP = "./FIXED_JUMPCUT_CHECK.bin"
    find_offsets(FIXED_JUMPCUT_FP)
