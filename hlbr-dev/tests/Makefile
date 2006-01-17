DEBUG=-g -Wall

all: test.o \
  test_interface_name.o \
  test_ethernet_type.o \
  test_ethernet_src.o \
  test_ethernet_dst.o \
  test_ip_src.o \
  test_ip_dst.o \
  test_ip_proto.o \
  test_ip_ttl.o \
  test_ip_check.o \
  test_icmp_type.o \
  test_icmp_code.o \
  test_tcp_src.o \
  test_tcp_dst.o \
  test_tcp_port.o \
  test_tcp_offset.o \
  test_udp_src.o \
  test_udp_dst.o \
  test_tcp_content.o \
  test_tcp_nocase.o \
  test_tcp_flags.o \
  test_udp_content.o \
  test_udp_nocase.o \
  test_dns_numquestions.o 


clean:
	rm -f *.o
	rm -f *core

test_udp_nocase.o: test_udp_nocase.c test_udp_nocase.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_udp_nocase.o test_udp_nocase.c $(DEBUG)

test_udp_content.o: test_udp_content.c test_udp_content.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_udp_content.o test_udp_content.c $(DEBUG)

test_dns_numquestions.o: test_dns_numquestions.c test_dns_numquestions.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_dns_numquestions.o test_dns_numquestions.c $(DEBUG)

test_tcp_stream_content.o: test_tcp_stream_content.c test_tcp_stream_content.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_tcp_stream_content.o test_tcp_stream_content.c $(DEBUG)

test_tcp_nocase.o: test_tcp_nocase.c test_tcp_nocase.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_tcp_nocase.o test_tcp_nocase.c $(DEBUG)

test_tcp_content.o: test_tcp_content.c test_tcp_content.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_tcp_content.o test_tcp_content.c $(DEBUG)

test_tcp_flags.o: test_tcp_flags.c test_tcp_flags.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_tcp_flags.o test_tcp_flags.c $(DEBUG)

test_tcp_offset.o: test_tcp_offset.c test_tcp_offset.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_tcp_offset.o test_tcp_offset.c $(DEBUG)
	
test_udp_port.o: test_udp_port.c test_udp_port.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_udp_port.o test_udp_port.c $(DEBUG)

test_udp_src.o: test_udp_src.c test_udp_src.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_udp_src.o test_udp_src.c $(DEBUG)

test_udp_dst.o: test_udp_dst.c test_udp_dst.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_udp_dst.o test_udp_dst.c $(DEBUG)

test_tcp_dst.o: test_tcp_dst.c test_tcp_dst.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_tcp_dst.o test_tcp_dst.c $(DEBUG)

test_tcp_src.o: test_tcp_src.c test_tcp_src.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_tcp_src.o test_tcp_src.c $(DEBUG)

test_icmp_code.o: test_icmp_code.c test_icmp_code.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_icmp_code.o test_icmp_code.c $(DEBUG)

test_icmp_type.o: test_icmp_type.c test_icmp_type.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_icmp_type.o test_icmp_type.c $(DEBUG)

test_ip_proto.o: test_ip_proto.c test_ip_proto.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_ip_proto.o test_ip_proto.c $(DEBUG)

test_ip_ttl.o: test_ip_ttl.c test_ip_ttl.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_ip_ttl.o test_ip_ttl.c $(DEBUG)

test_ip_check.o: test_ip_check.c test_ip_check.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_ip_check.o test_ip_check.c $(DEBUG)

test_ip_dst.o: test_ip_dst.c test_ip_dst.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_ip_dst.o test_ip_dst.c $(DEBUG)

test_ip_src.o: test_ip_src.c test_ip_src.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_ip_src.o test_ip_src.c $(DEBUG)

test_ethernet_dst.o: test_ethernet_dst.c test_ethernet_dst.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_ethernet_dst.o test_ethernet_dst.c $(DEBUG)

test_ethernet_src.o: test_ethernet_src.c test_ethernet_src.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_ethernet_src.o test_ethernet_src.c $(DEBUG)

test_ethernet_type.o: test_ethernet_type.c test_ethernet_type.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_ethernet_type.o test_ethernet_type.c $(DEBUG)

test_interface_name.o: test_interface_name.c test_interface_name.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test_interface_name.o test_interface_name.c $(DEBUG)
	
test.o: test.c test.h ../config.h ../engine/hogwash.h
	$(CC) -c -o test.o test.c $(DEBUG)
