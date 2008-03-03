DEBUG=-g -Wall

all: decode.o \
decode_interface.o \
decode_ethernet.o \
decode_ip.o \
decode_ip_defrag.o \
decode_icmp.o \
decode_udp.o \
decode_tcp.o \
decode_uri.o \
decode_dns.o \
decode_arp.o

clean:
	rm -f *.o
	rm -f *core

decode_arp.o: decode_arp.c decode_arp.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_arp.o decode_arp.c $(DEBUG)	

decode_dns.o: decode_dns.c decode_dns.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_dns.o decode_dns.c $(DEBUG)	

decode_uri.o: decode_uri.c decode_uri.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_uri.o decode_uri.c $(DEBUG)

decode_tcp_stream.o: decode_tcp_stream.c decode_tcp_stream.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_tcp_stream.o decode_tcp_stream.c $(DEBUG)	

decode_tcp.o: decode_tcp.c decode_tcp.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_tcp.o decode_tcp.c $(DEBUG)	

decode_udp.o: decode_udp.c decode_udp.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_udp.o decode_udp.c $(DEBUG)	

decode_icmp.o: decode_icmp.c decode_icmp.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_icmp.o decode_icmp.c $(DEBUG)	

decode_ip_defrag.o: decode_ip_defrag.c decode_ip_defrag.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_ip_defrag.o decode_ip_defrag.c $(DEBUG)	

decode_ip.o: decode_ip.c decode_ip.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_ip.o decode_ip.c $(DEBUG)	

decode_ethernet.o: decode_ethernet.c decode_ethernet.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_ethernet.o decode_ethernet.c $(DEBUG)	
	
decode_interface.o: decode_interface.c decode_interface.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode_interface.o decode_interface.c $(DEBUG)	
	
decode.o: decode.c decode.h ../config.h ../engine/hlbr.h
	$(CC) -c -o decode.o decode.c $(DEBUG)
