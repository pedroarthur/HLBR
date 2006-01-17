DEBUG=-g -Wall

all: module.o \
module_web_unique.o \
module_dns_unique.o \
module_dynamic.o  \
module_ats2.o \
module_covert.o 

clean:
	rm -f *.o *.so *.c~ *.h~
	rm -f *core

mod_example.so: mod_example.c ../config.h ../engine/hogwash.h
	$(CC) --shared -o mod_example.so mod_example.c $(DEBUG)

module_covert.o: module_covert.c module_covert.h ../config.h ../engine/hogwash.h
	$(CC) -c -o module_covert.o module_covert.c $(DEBUG)

module_ats2.o: module_ats2.c module_ats2.h ../config.h ../engine/hogwash.h
	$(CC) -c -o module_ats2.o module_ats2.c $(DEBUG)

module_ats.o: module_ats.c module_ats.h ../config.h ../engine/hogwash.h
	$(CC) -c -o module_ats.o module_ats.c $(DEBUG)

module_dns_unique.o: module_dns_unique.c module_dns_unique.h ../config.h ../engine/hogwash.h
	$(CC) -c -o module_dns_unique.o module_dns_unique.c $(DEBUG)

module_web_unique.o: module_web_unique.c module_web_unique.h ../config.h ../engine/hogwash.h
	$(CC) -c -o module_web_unique.o module_web_unique.c $(DEBUG)

module_dynamic.o: module_dynamic.c ../config.h ../engine/hogwash.h
	$(CC) -c -o module_dynamic.o module_dynamic.c $(DEBUG)
	
module.o: module.c module.h ../config.h ../engine/hogwash.h
	$(CC) -c -o module.o module.c $(DEBUG)
