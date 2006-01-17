DEBUG=-g -Wall


all: action.o \
action_drop.o \
action_alert_console.o \
action_alert_file.o \
action_dump_packet.o \
action_route_sip.o \
action_bns.o \
action_alert_mysql.o \
action_alert_syslog.o \
action_alert_email.o \
action_alert_socket.o \
action_alert_listensocket.o 

clean:
	rm -f *.o *.c~
	rm -f *core

action_alert_listensocket.o: action_alert_listensocket.c action_alert_listensocket.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_alert_listensocket.o action_alert_listensocket.c $(DEBUG)

action_alert_socket.o: action_alert_socket.c action_alert_socket.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_alert_socket.o action_alert_socket.c $(DEBUG)

action_alert_email.o: action_alert_email.c action_alert_email.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_alert_email.o action_alert_email.c $(DEBUG)

action_alert_syslog.o: action_alert_syslog.c action_alert_syslog.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_alert_syslog.o action_alert_syslog.c $(DEBUG)

action_alert_mysql.o: action_alert_mysql.c action_alert_mysql.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_alert_mysql.o action_alert_mysql.c $(DEBUG)

action_bns.o: action_bns.c action_bns.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_bns.o action_bns.c $(DEBUG)

action_route_sip.o: action_route_sip.c action_route_sip.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_route_sip.o action_route_sip.c $(DEBUG)

action_dump_packet.o: action_dump_packet.c action_dump_packet.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_dump_packet.o action_dump_packet.c $(DEBUG)

action_alert_file.o: action_alert_file.c action_alert_file.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_alert_file.o action_alert_file.c $(DEBUG)

action_alert_console.o: action_alert_console.c action_alert_console.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_alert_console.o action_alert_console.c $(DEBUG)

action_drop.o: action_drop.c action_drop.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action_drop.o action_drop.c $(DEBUG)

action.o: action.c action.h ../config.h ../engine/hogwash.h
	$(CC) -c -o action.o action.c $(DEBUG)
