all: target tracer

target: target.c
	x86_64-linux-musl-gcc -static -Os target.c -o target

tracer: tracer.c target
	gcc -DFUNC_ADDR=0x$(shell nm -g target | awk '$$3=="soma" {print $$1}') tracer.c -o tracer

clean:
	rm -f target tracer

.PHONY: clean
