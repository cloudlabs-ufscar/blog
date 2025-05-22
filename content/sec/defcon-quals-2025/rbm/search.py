import re
import sys

with open('rbm.c') as f:
    data = f.read()

for m in re.finditer(r'_BYTE v27\[(\d+)\];(.*?)  v30 = (\d+);\n  v29 = (\d+);\n', data, re.DOTALL):
    arr_size, garbage, len1, len2 = m.groups()
    arr_size = int(arr_size)
    garbage = len(garbage)
    len1 = int(len1)
    len2 = int(len2)
    assert garbage == 194
    if len1 * len2 >= arr_size + 8:
        print('line', data[:m.start()].count('\n'))
        print(len1, len2, arr_size)
        sys.exit(1337)

for m in re.finditer(r'_BYTE v12\[(\d+)\];(.*?)  v8 = (\d+);', data, re.DOTALL):
    arr_size, garbage, can_copy = m.groups()
    arr_size = int(arr_size)
    #garbage = len(garbage)
    can_copy = int(can_copy)
    if can_copy >= arr_size + 8:
        print('line', data[:m.start()].count('\n'))
        print(can_copy, arr_size)
        sys.exit(1337)
