from iced_x86 import Decoder, DecoderOptions, Mnemonic, Instruction, BlockEncoder, Code

def jumpcut(FIXED_CHECK_FP, FIXED_JUMPCUT_FP):
    CODE = b""
    with open(FIXED_CHECK_FP, "rb") as file:
        CODE = file.read()
    FIXED_CODE = bytearray(CODE[:])
    print(len(FIXED_CODE))
    IP = 0
    decoder = Decoder(64, CODE, ip=IP)
    processed_instr = set()
    def fixJumpLoop(instr):
        stack = []
        stack.append(instr)
        
        offset = instr.near_branch_target
        next_instr = Decoder(64, CODE[offset:], ip=offset).decode()
        while next_instr.mnemonic == Mnemonic.JMP:
            print(hex(next_instr.ip), len(stack) * "  ", next_instr)
            stack.append(next_instr)
            offset = next_instr.near_branch_target
            next_instr = Decoder(64, CODE[offset:], ip=offset).decode()
        # here instr is not a jump
        # offset is the offset to the first nonjmp instr
        
        for instr in stack:
            for target in [next_instr, *stack[1::-1]]:
                encoder = BlockEncoder(64)
                
                patched_instr = Instruction.create_branch(Code.JMP_REL32_64, target.ip)
                encoder.add_many([patched_instr])
                patched_instr_bytes = encoder.encode(instr.ip)
                # instr is 4
                # patch is 5
                # 2 nops
                
                _start_nop = CODE[instr.ip + instr.len:]
                current_nops = 0
                while current_nops < len(_start_nop) and _start_nop[current_nops] == 0x90:
                    current_nops += 1
                
                if len(patched_instr_bytes) > (instr.len + current_nops):
                    # happens to not be reached
                    print("CRY", len(patched_instr_bytes) - instr.len)
                else:
                    FIXED_CODE[instr.ip:instr.ip + len(patched_instr_bytes)] = patched_instr_bytes
                    n_nops = instr.len - len(patched_instr_bytes)
                    if n_nops > 0:
                        FIXED_CODE[instr.ip + len(patched_instr_bytes): instr.ip + instr.len] = b"\x90" * n_nops
                    processed_instr.add(instr.ip)
                    break
    i = 0
    for instr in decoder:
        if instr.mnemonic == Mnemonic.JMP and instr.ip not in processed_instr:
            fixJumpLoop(instr)
            i += 1
            
            if i % 100 == 0:
                print(100 * instr.ip / len(FIXED_CODE)) # percentage
    with open(FIXED_JUMPCUT_FP, "wb") as file:
        file.write(FIXED_CODE)

if __name__ == "__main__":
    FIXED_CHECK_FP = "./FIXED_CHECK.bin"
    FIXED_JUMPCUT_FP = "../FIXED_JUMPCUT_CHECK.bin"
    jumpcut(FIXED_CHECK_FP, FIXED_JUMPCUT_FP)
