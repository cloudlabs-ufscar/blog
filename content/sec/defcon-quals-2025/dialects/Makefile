all: test brute_hash example.com.crt

test: test.c libchina.o
	gcc -no-pie $^ -o $@

brute_hash: brute_hash.c libchina.o libsha.o
	gcc -no-pie -Ofast -fopenmp $^ -o $@

libchina.o: libchina.asm
	nasm -f elf64 $< -o $@

libsha.o: sha512.c 
	gcc -Ofast -c sha512.c -o libsha.o 

example.com.crt:
	openssl req -newkey rsa:2048 -nodes -keyout example.com.key -x509 -subj '/CN=lol/' -days 365 -out example.com.crt
