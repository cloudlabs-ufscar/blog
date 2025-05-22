+++
date = 2025-05-21T18:00:00-03:00
draft = false
title = "DEF CON Quals 2025"
description = "DEF CON Quals 2025 — writeups"
tags = ['CTF', 'reversing', 'crypto']
categories = []
featured = true
[params]
  locale = "en"
+++

More than one month has past since DEF CON Quals, but we were so exhausted by it only now we managed to put together this set of write-ups. This year, several [CTF-BR](https://ctf-br.org) affiliated teams united to form `pwn de queijo` (a pun with [pão de queijo](https://en.wikipedia.org/wiki/Cheese_bun)). Together, we managed to achieve top17, the best position achieved by a Brazilian team until now. Let's keep training to get qualified to the Finals next year :D

Unfortunately, the new Cloudlabs students did not manage to participate, since they had just joined the group. However, we had the pleasure to play with Vinicius, a long time Cloudlabs student, and Daniel and Miguel, two former students who now work at [Magalu Cloud](https://magalu.cloud).

![Cloudlabs alumni](./photos/Hackaflag-46.jpg)

We are grateful to [Flipside](https://flipside.com.br) for providing such a nice space for us to gather together.

Now let's get to the write-ups.

## rainbow mountain

We were given the [rbm](./rbm/rbm) binary.

Since the binary is statically linked, and since it had strings referencing `GCC: (Debian 12.2.0-14) 12.2.0`, which is a version of gcc shipped with Debian bookworm, we started by generating FLIRT signatures for libc and libstdc++ from that distro, and loaded them into IDA Pro.

Then, we spent a couple of hours reversing the main program, since it had a lot of C++ indirection going on and we thought some important behavior could be hidden there. However, it turns out the program simply called 0x4E8440 (which we named `fill_func_arr`) to load a big array of functions, then asked the user which of these functions they wanted to call, and finally asked for some base64 encoded data to pass as an argument to the chosen function. Lesson learned: start thinking simple; only if that does not work, carry out a deep analysis.

We noticed the first two functions of the array (0x404450 and 0x404780) did the same thing, only dimensions of the buffers were different. They copied the provided string into a grid (9x8 or 7x5, respectively) called `arr` in boustrophedonic order (i.e. consecutive rows alternated between left-to-right and right-to-left). In the stack, just after `arr`, there was a small buffer called `target`. After copying the provided string to `arr`, the function checked if `target` contained some `wanted` string.

In short, we needed to find which function had `arr` dimensions shorter than the grid size. Then, it would be possible to overflow `arr` and overwrite `target` with the desired string.

Since there were a lot of functions, we needed to automate the search. We used IDA Pro menu `File -> Produce File -> Create C File` to decompile the entire program into [rbm.c](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/rbm/rbm.c).

We noticed one of the functions we still didn't manually analyze had the following structure:

```c
  _BYTE v27[64]; // [rsp+60h] [rbp-60h] BYREF
  __int64 v28; // [rsp+A0h] [rbp-20h]
  __int64 v29; // [rsp+A8h] [rbp-18h]
  __int64 v30; // [rsp+B0h] [rbp-10h]
  __int64 v31; // [rsp+B8h] [rbp-8h]

  v31 = a1;
  v30 = 9;
  v29 = 7;
  v28 = 0;
```

where `v27` is `arr`, `v28` is `target`, and `v30`x`v29` is the grid size. Then, we wrote a Python script to look for a function allowing to overflow `arr` at least by 8 bytes (size of `target`). 

```python
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
```

Unfortunately, there was no such function.

We got back at the decompiled code and realized not all of the functions from the big array followed the template we were looking for.

We spotted the first function we found (0x405730) which was different from the template we previously analyzed. It simply copied the input string to `arr`. It was much simpler since it did not reorder the string contents. The following excerpt was extracted from that function:

```c
  _BYTE v12[80]; // [rsp+28h] [rbp-68h] BYREF
  __int64 v13; // [rsp+78h] [rbp-18h]
  __int64 v14; // [rsp+80h] [rbp-10h]
  __int64 v15; // [rsp+88h] [rbp-8h]

  v15 = a1;
  v14 = 79;
  v13 = 0;
  v11 = 0x5A43474C43613378LL;
  v9 = string_len_(a1);
  v8 = 83;
```

where `v12` is `arr`, `v13` is `target`, `v11` is `wanted`, and `v8` is the maximum amount of bytes copied from the input string to `arr`.

Notice the function above allows to overflow `arr` by 3 bytes, but that is not enough to replace `target` with the `wanted` value. Once again, we need to find a function allowing to overflow at least 8 bytes.

Now we complement our Python script with a regex for the newly discovered function template.

```python
for m in re.finditer(r'_BYTE v12\[(\d+)\];(.*?)  v8 = (\d+);', data, re.DOTALL):
    arr_size, garbage, can_copy = m.groups()
    arr_size = int(arr_size)
    #garbage = len(garbage)
    can_copy = int(can_copy)
    if can_copy >= arr_size + 8:
        print('line', data[:m.start()].count('\n'))
        print(can_copy, arr_size)
        sys.exit(1337)
```

The search finally returned something interesting:

```text
line 153797
72 64
```

Around that line in [rbm.c](https://github.com/cloudlabs-ufscar/blog/blob/main/content/sec/defcon-quals-2025/rbm/rbm.c), we had the following function:

```c
_BOOL8 __fastcall sub_4B82B0(__int64 a1)
{
  __int64 v1; // rax
  _QWORD *v2; // rax
  __int64 v3; // rax
  _QWORD *v4; // rax
  __int64 v5; // rax
  __int64 v7; // [rsp+8h] [rbp-88h]
  __int64 v8; // [rsp+10h] [rbp-80h] BYREF
  __int64 v9; // [rsp+18h] [rbp-78h] BYREF
  __int64 v10; // [rsp+20h] [rbp-70h]
  __int64 v11; // [rsp+28h] [rbp-68h]
  _BYTE v12[64]; // [rsp+30h] [rbp-60h] BYREF
  __int64 v13; // [rsp+70h] [rbp-20h]
  __int64 v14; // [rsp+78h] [rbp-18h]
  __int64 v15; // [rsp+80h] [rbp-10h]

  v15 = a1;
  if ( (sub_4042E0(a1) & 1) != 0 )
  {
    v14 = 58;
    v13 = 0;
    v11 = 0x3447784339354946LL;
    v9 = string_len_(v15);
    v8 = 72;
    v10 = *min(&v9, &v8);
    v7 = sub_4F5810((__int64)v12);
    v1 = sub_4F52B0(v15);
    j_ifunc_5CC6D0(v7, v1, v10);
    v2 = operator_write_stream(std_cerr, (__int64)"target: ");
    unknown_libname_550(v2, sub_4F50B0);
    v3 = std::ostream::_M_insert<unsigned long>();
    operator_write(v3, std::endl<char,std::char_traits<char>>);
    v4 = operator_write_stream(std_cerr, (__int64)"wanted: ");
    unknown_libname_550(v4, sub_4F50B0);
    v5 = std::ostream::_M_insert<unsigned long>();
    operator_write(v5, std::endl<char,std::char_traits<char>>);
    return v13 == v11;
  }
  else
  {
    return 0;
  }
}
```

It did not follow exactly our template, since it checked the input string with `sub_4042E0` before copying it to `arr`. We analyzed `sub_4042E0` and discovered it checked if the string was a palindrome.

So far so good, now we have everything we need to set up an overflow.

We got back to `fill_func_array` to see `sub_4B82B0` is in position `1576` of the function array.

We fired ipython to mount a palindrome input ending with the `wanted` value and to encode it to base64.

```python
In [1]: from pwn import *

In [2]: wanted = p64(0x3447784339354946)

In [3]: wanted
Out[3]: b'FI59CxG4'

In [4]: base64.b64encode(wanted[::-1] + (64-8)*b'A' + wanted)
Out[4]: b'NEd4Qzk1SUZBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUZJNTlDeEc0'
```

Finally, we tested it locally and it worked!

```text
$ ./rbm
rainbow mountain
function index:
1576
picked 7fffc58e0560
base64'd input: NEd4Qzk1SUZBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUZJNTlDeEc0
decoded 72 bytes
target: 3447784339354946
wanted: 3447784339354946
correct!
the flag is no flag configured! contact orga
```

And that's it. No point in showing the flag we received from the server, since they provided a different random flag for each team (as part of their infrastructure for *flag sharing prevention*).

## dialects

TBW

![The (Relentless) Crypto Mage](./photos/IMG_5008.jpg)
