DEBUG=-g -Wall 

all: hlbr.o  \
parse_config.o  \
parse_rules.o   \
main_loop.o     \
bits.o          \
session.o       \
num_list.o      \
message.o       \
cache.o         \
jtree.o 	\
hlbrlib.o

clean:
	rm -f *.o
	rm -f *core

hlbrlib.o: hlbrlib.c hlbrlib.h ../config.h hlbr.h
	$(CC) -c -o hlbrlib.o hlbrlib.c $(DEBUG)

cache.o: cache.c cache.h ../config.h hlbr.h
	$(CC) -c -o cache.o cache.c $(DEBUG)

message.o: message.c message.h ../config.h hlbr.h
	$(CC) -c -o message.o message.c $(DEBUG)

num_list.o: num_list.c num_list.h ../config.h hlbr.h
	$(CC) -c -o num_list.o num_list.c $(DEBUG)
	
jtree.o: jtree.c jtree.h ../config.h hlbr.h
	$(CC) -c -o jtree.o jtree.c $(DEBUG)

bmtree.o: bmtree.c bmtree.h ../config.h hlbr.h
	$(CC) -c -o bmtree.o bmtree.c $(DEBUG)

session.o: session.c session.h ../config.h hlbr.h
	$(CC) -c -o session.o session.c $(DEBUG)

main_loop.o: main_loop.c main_loop.h ../config.h hlbr.h
	$(CC) -c -o main_loop.o main_loop.c $(DEBUG)

parse_rules.o: parse_rules.c parse_rules.h ../config.h hlbr.h
	$(CC) -c -o parse_rules.o parse_rules.c $(DEBUG)

parse_config.o: parse_config.c parse_config.h ../config.h hlbr.h
	$(CC) -c -o parse_config.o parse_config.c $(DEBUG)

bits.o: bits.c bits.h
	$(CC) -c -o bits.o bits.c $(DEBUG)

hlbr.o: hlbr.c hlbr.h ../config.h
	$(CC) -c -o hlbr.o hlbr.c $(DEBUG)
