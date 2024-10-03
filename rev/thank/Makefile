all: clean thank payload.so

dist: clean thank
	zip export.zip thank

thank: thank.c
	gcc -s thank.c -o thank

payload.so: payload.c
	gcc -shared payload.c -o payload.so

clean:
	rm -f thank *.so export.zip
