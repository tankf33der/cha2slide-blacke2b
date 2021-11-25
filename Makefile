all:
	gcc -fPIC -c blake2b.c -o blake2b.o
	gcc -shared -Wl,-soname,libslide.so.0 -o libslide.so.0 blake2b.o -lc
	sudo cp -uf libslide.so.0 /usr/local/lib
	sudo ldconfig
clean:
	rm -rf *.o *.0
