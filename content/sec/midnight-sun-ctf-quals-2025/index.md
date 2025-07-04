+++
date = 2025-05-27T11:00:00-03:00
draft = false
title = "MidNight Sun CTF 2025"
description = "MidNight Sun CTF 2025 — writeup for crypto challenge"
tags = ['CTF', 'crypto']
categories = []
featured = true
[params]
  locale = "en"
+++

Two weeks ago (05/17), we (ELT) participated in MidNight Sun CTF 2025 Quals, a HackingForSoju's annual CTF event to promote competition around the world. On this writeup, we will talk about a crypto chall, solved by Danilo (dant3) and Lucas (kyo).

## Oldchall
The challenge had the following description
```
ssh bionic@oldchall-wzmj3o9b.ctf.pro / Password: F33lOldY3t

We posted the quals so much that this chall is straight from 2018.
```

The initial step was to log in via ssh using the credentials provided, granting access to the challenge's remote machine. using `ls -a` for a complete list, two relevant files were found
```bash
> ls -a
.
..
.viminfo
flag.txt
```

When reading the contents of the file `flag.txt`, the contents were encrypted with `VimCrypt~01`, but the target environment blocked the use of `scp` to copy the file to the local environment, so it was necessary to convert to base64 and decrypt locally, obtaining:
```
VimCrypt~01!�p��r�E�Ѭ����ƈ�ɲŕW����i��>a��
���X��0ؕ Ԡ��}�wN��yʮ�~�#V�#ej��>9𛹽��t��l�;
�sE�3�>�c�v
```

Using `strings .viminfo`, records were found of changes to the file containing the flag indicating the start and end of the file
plainhead.txt:
```
The flag I'm planning to use in 2025 is:
```

plaintail.txt:
```
Awesome flag, right?
```

After discovering the beginning of the file's contents and the end, we went on to understand how it was possible to break VimCrypt in version 01. 
By default, you can encrypt a file using vim simply by using `:X`, allowing you to set a password. In this method, when you open the file, Vim will ask you for a password to open the file, which is used as the decryption key. VimCrypt has 3 versions and in our case we were dealing with the least secure, which uses the zip encryption technique. Knowing which encryption technique was used, we needed to know at least 12 bytes of content and their position in order to carry out a plaintext attack. As we knew both the head and tail of the file, we converted the encrypted file into a binary file and then used `bkcrack` to break it.

cipher.bin
```bash
> dd if=Flag\ from\ Server.txt of=cipher.bin bs=1 skip=12
```

```bash
> bkcrack -C cipher.bin -c 0 -P head.txt -p 0 
keys: 9fa69309 af4c72de 85998520
```

`bkcrack` returns 3 keys that can be used to finally crack the file:
```bash
> bkcrack -c cipher.bin -k 9fa69309 af4c72de 85998520 -d decrypted.txt
```

Thus, we found the challenge flag:
decrypted.txt:
```
The flag I'm planning to use in 2025 is:
midnight{w1nZ1p_m0r3_L1k3_v1mz1P_am1rit3}
Awesome flag, right?

```

----- 
For now, we're done. Thanks for reading! If you ever need to deploy cloud-based infrastructure in Brazil, please consider our great partner [Magalu Cloud](https://magalu.cloud).



