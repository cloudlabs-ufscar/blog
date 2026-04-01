from iced_x86 import Decoder, DecoderOptions, Mnemonic, Instruction, BlockEncoder, Code

def fix_check(CHECK_FP, FIXED_CHECK_FP):
    CODE = b""
    with open(CHECK_FP, "rb") as file:
        CODE = file.read()
    FIXED_CODE = bytearray(CODE[:])
    print(len(FIXED_CODE))
    IP = 0
    decoder = Decoder(64, CODE, ip=IP)
    decoder_iter = iter(decoder)
    instructions = []
    instructions.append(next(decoder_iter))
    instructions.append(next(decoder_iter))
    instructions.append(next(decoder_iter))
    instructions.append(next(decoder_iter))
    instructions.append(next(decoder_iter))
    allJumps = set()
    allJumps.add(Mnemonic.JG)
    allJumps.add(Mnemonic.JLE)
    allJumps.add(Mnemonic.JL)
    allJumps.add(Mnemonic.JGE)
    allJumps.add(Mnemonic.JB)
    allJumps.add(Mnemonic.JAE)
    allJumps.add(Mnemonic.JS)
    allJumps.add(Mnemonic.JNS)
    allJumps.add(Mnemonic.JO)
    allJumps.add(Mnemonic.JNO)
    allJumps.add(Mnemonic.JA)
    allJumps.add(Mnemonic.JBE)
    allJumps.add(Mnemonic.JP)
    allJumps.add(Mnemonic.JNP)
    allJumps.add(Mnemonic.JE)
    allJumps.add(Mnemonic.JNE)
    jumpOpposite = {
        Mnemonic.JG: Mnemonic.JLE,
        Mnemonic.JGE: Mnemonic.JL,
        Mnemonic.JL: Mnemonic.JGE,
        Mnemonic.JLE: Mnemonic.JG,
        Mnemonic.JB: Mnemonic.JAE,
        Mnemonic.JS: Mnemonic.JNS,
        Mnemonic.JNS: Mnemonic.JS,
        Mnemonic.JO: Mnemonic.JNO,
        Mnemonic.JNO: Mnemonic.JO,
        Mnemonic.JA: Mnemonic.JBE,
        Mnemonic.JBE: Mnemonic.JA,
        Mnemonic.JB: Mnemonic.JAE,
        Mnemonic.JAE: Mnemonic.JB,
        Mnemonic.JP: Mnemonic.JNP,
        Mnemonic.JNP: Mnemonic.JP,
        Mnemonic.JE: Mnemonic.JNE,
        Mnemonic.JNE: Mnemonic.JE,
    }
    # patches dead code ofuscation
    while instructions:
        instr = instructions[0]
        if instr.mnemonic in allJumps:
            
            oppositeJmpMnemonic = jumpOpposite[instr.mnemonic]
            oppositeJmp = next(filter(lambda ins: ins.mnemonic == oppositeJmpMnemonic, instructions[1:]), None)
            
            
            if oppositeJmp:
                
                if oppositeJmp.near_branch_target == instr.near_branch_target:
                    
                    new_instr = Instruction.create_branch(Code.JMP_REL32_64, instr.near_branch_target)
                    
                    encoder = BlockEncoder(64)
                    encoder.add_many([new_instr])
                    
                    new_instr_bytes = encoder.encode(instr.ip)
                    FIXED_CODE[instr.ip:instr.ip + len(new_instr_bytes)] = new_instr_bytes
                    
                    how_many_nops = oppositeJmp.next_ip - (instr.ip + len(new_instr_bytes))
                    FIXED_CODE[instr.ip + len(new_instr_bytes): oppositeJmp.next_ip] = b"\x90" * how_many_nops
            
            #print()
        else:
            pass
        instructions = instructions[1:]
        try:
            instructions.append(next(decoder_iter))
        except:
            pass
    with open(FIXED_CHECK_FP, "wb") as file:
        file.write(FIXED_CODE)

if __name__ == "__main__":
    CHECK_FP = "../RT_RCDATA(10)__CHECK__0.bin" # resource exported using die.exe
    FIXED_CHECK_FP = "../FIXED_CHECK.bin"
    fix_check(CHECK_FP, FIXED_CHECK_FP)
