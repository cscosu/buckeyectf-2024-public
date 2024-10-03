all: clean spaceman

dist: clean spaceman
	echo "bctf{fake_flag}" > flag.txt
	zip export.zip spaceman spaceman.c Dockerfile Makefile run.sh flag.txt

spaceman: spaceman.c
	/opt/riscv/bin/riscv64-unknown-linux-gnu-gcc -w spaceman.c -o spaceman -static -fno-zero-initialized-in-bss
clean:
	rm -f spaceman export.zip
