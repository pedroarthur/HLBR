DEBUG=-g -Wall 

all: hogwash.o  \
parse_config.o  \
parse_rules.o   \
parse_snort.o	\
main_loop.o     \
bits.o          \
session.o       \
num_list.o      \
message.o       \
cache.o         \
jtree.o 	\
hoglib.o

clean:
	rm -f *.o
	rm -f *core

hoglib.o: hoglib.c hoglib.h ../config.h hogwash.h
	$(CC) -c -o hoglib.o hoglib.c $(DEBUG)

cache.o: cache.c cache.h ../config.h hogwash.h
	$(CC) -c -o cache.o cache.c $(DEBUG)

message.o: message.c message.h ../config.h hogwash.h
	$(CC) -c -o message.o message.c $(DEBUG)

num_list.o: num_list.c num_list.h ../config.h hogwash.h
	$(CC) -c -o num_list.o num_list.c $(DEBUG)
	
jtree.o: jtree.c jtree.h ../config.h hogwash.h
	$(CC) -c -o jtree.o jtree.c $(DEBUG)

bmtree.o: bmtree.c bmtree.h ../config.h hogwash.h
	$(CC) -c -o bmtree.o bmtree.c $(DEBUG)

session.o: session.c session.h ../config.h hogwash.h
	$(CC) -c -o session.o session.c $(DEBUG)

main_loop.o: main_loop.c main_loop.h ../config.h hogwash.h
	$(CC) -c -o main_loop.o main_loop.c $(DEBUG)

parse_snort.o: parse_snort.c parse_snort.h ../config.h hogwash.h
	$(CC) -c -o parse_snort.o parse_snort.c $(DEBUG)

parse_rules.o: parse_rules.c parse_rules.h ../config.h hogwash.h
	$(CC) -c -o parse_rules.o parse_rules.c $(DEBUG)

parse_config.o: parse_config.c parse_config.h ../config.h hogwash.h
	$(CC) -c -o parse_config.o parse_config.c $(DEBUG)

bits.o: bits.c bits.h
	$(CC) -c -o bits.o bits.c $(DEBUG)

hogwash.o: hogwash.c hogwash.h ../config.h
	$(CC) -c -o hogwash.o hogwash.c $(DEBUG)
