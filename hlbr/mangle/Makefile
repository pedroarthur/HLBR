DEBUG=-g -Wall


all: mangle.o mangle_hard_mac.o

clean:
	rm -f *.o
	rm -f *core

mangle_hard_mac.o: mangle_hard_mac.c mangle_hard_mac.h ../config.h ../engine/hogwash.h
	$(CC) -c -o mangle_hard_mac.o mangle_hard_mac.c $(DEBUG)

mangle.o: mangle.c mangle.h ../config.h ../engine/hogwash.h
	$(CC) -c -o mangle.o mangle.c $(DEBUG)
