DEBUG=-g -Wall

all: packet.o \
packet_linux_raw.o \
packet_obsd_bpf.o \
packet_osx_bpf.o \
packet_tcpdump.o \
packet_solaris_dlpi.o

clean:
	rm -f *.o
	rm -f *core

packet_solaris_dlpi.o: packet_solaris_dlpi.c packet_solaris_dlpi.h ../config.h ../engine/hlbr.h
	$(CC) -c -o packet_solaris_dlpi.o packet_solaris_dlpi.c $(DEBUG)

packet_tcpdump.o: packet_tcpdump.c packet_tcpdump.h ../config.h ../engine/hlbr.h
	$(CC) -c -o packet_tcpdump.o packet_tcpdump.c $(DEBUG)
	
packet_osx_bpf.o: packet_osx_bpf.c packet_osx_bpf.h ../config.h ../engine/hlbr.h
	$(CC) -c -o packet_osx_bpf.o packet_osx_bpf.c $(DEBUG)

packet_obsd_bpf.o: packet_obsd_bpf.c packet_obsd_bpf.h ../config.h ../engine/hlbr.h
	$(CC) -c -o packet_obsd_bpf.o packet_obsd_bpf.c $(DEBUG)

packet_linux_raw.o: packet_linux_raw.c packet_linux_raw.h ../config.h ../engine/hlbr.h
	$(CC) -c -o packet_linux_raw.o packet_linux_raw.c $(DEBUG)

packet_cache.o: packet_cache.c packet_cache.h ../config.h ../engine/hlbr.h
	$(CC) -c -o packet_cache.o packet_cache.c $(DEBUG)
	
packet.o: packet.c packet.h ../config.h ../engine/hlbr.h
	$(CC) -c -o packet.o packet.c $(DEBUG)
