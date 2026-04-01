from fix_check import fix_check
from jumpcut import jumpcut
from find_offsets import find_offsets
from find_weird_string import find_weird_string
from magic import get_magic
from weird import solve
from decrypt import decrypt
from extractor import extract
import shutil

with open("./license.bin", "wb") as license:
    pass

fix_check("CHECK.bin", "./FIXED_CHECK.bin")
#jumpcut("./FIXED_CHECK.bin", "./FIXED_JUMPCUT_CHECK.bin")
shutil.copy("./FIXED_CHECK.bin", "./FIXED_JUMPCUT_CHECK.bin")
offsets = find_offsets("./FIXED_JUMPCUT_CHECK.bin")
weird_string = find_weird_string("./FIXED_JUMPCUT_CHECK.bin", offsets)
magic = get_magic("./FIXED_JUMPCUT_CHECK.bin")
key = solve(magic, weird_string)
decrypt("./MATRYOSHKA.bin", "./license.bin", "NextDoll.dll")
print(key)

extract("NextDoll.dll", "./NextCheck.bin", "./NextMatryoshka.bin")

while True:
    fix_check("./NextCheck.bin", "./NextCheckFixed.bin")
    #jumpcut("./NextCheckFixed.bin", "./NextCheckFixedJumpcut.bin")
    
    shutil.copy("./NextCheckFixed.bin", "./NextCheckFixedJumpcut.bin")
    offsets = find_offsets("./NextCheckFixedJumpcut.bin")
    weird_string = find_weird_string("./NextCheckFixedJumpcut.bin", offsets)
    magic = get_magic("./NextCheckFixedJumpcut.bin")
    key = solve(magic, weird_string)
    decrypt("./NextMatryoshka.bin", "./license.bin", "./NextDoll.dll")
    print(key)
    extract("NextDoll.dll", "./NextCheck.bin", "./NextMatryoshka.bin")
