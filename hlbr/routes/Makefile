DEBUG=-g -Wall


all: route.o \
route_macfilter.o \
route_simple_bridge.o \
route_dip.o \
route_sip.o \
route_broadcast.o \
route_arp.o \
route_interface.o \
route_bns.o

clean:
	rm -f *.o
	rm -f *core

route_bns.o: route_bns.c route_bns.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route_bns.o route_bns.c $(DEBUG)

route_interface.o: route_interface.c route_interface.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route_interface.o route_interface.c $(DEBUG)

route_arp.o: route_arp.c route_arp.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route_arp.o route_arp.c $(DEBUG)

route_broadcast.o: route_broadcast.c route_broadcast.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route_broadcast.o route_broadcast.c $(DEBUG)

route_sip.o: route_sip.c route_sip.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route_sip.o route_sip.c $(DEBUG)

route_dip.o: route_dip.c route_dip.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route_dip.o route_dip.c $(DEBUG)

route_simple_bridge.o: route_simple_bridge.c route_simple_bridge.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route_simple_bridge.o route_simple_bridge.c $(DEBUG)

route_macfilter.o: route_macfilter.c route_macfilter.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route_macfilter.o route_macfilter.c $(DEBUG)

route.o: route.c route.h ../config.h ../engine/hlbr.h
	$(CC) -c -o route.o route.c $(DEBUG)
