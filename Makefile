.PHONY: all clean install uninstall
CC = gcc
CFLAGS := -g0 -Wall -std=c11
CFLAGS += -I./lib/libmnl/include -I./lib/libnetfilter_queue/include -I./lib/libnetfilter_queue -I./lib/libnetlink/include -I./lib/libnfnetlink/include
LIBS = ./lib/libnetfilter_queue/src/.libs/libnetfilter_queue.a ./lib/libnetlink/libnetlink.a ./lib/libnfnetlink/src/.libs/libnfnetlink.a ./lib/libmnl/src/.libs/libmnl.a
SRC_FILES = ./nfqttl.c

all: libmnl libnetlink libnfnetlink libnetfilter_queue nfqttl

clean: 
	cd ./lib/libmnl && $(MAKE) clean
	cd ./lib/libnetlink && $(MAKE) clean
	cd ./lib/libnfnetlink && $(MAKE) clean
	cd ./lib/libnetfilter_queue && $(MAKE) clean
	rm -f *.o *.a nfqttl

distclean: 
	cd ./lib/libmnl && $(MAKE) distclean
	cd ./lib/libnetlink && $(MAKE) clean
	cd ./lib/libnfnetlink && $(MAKE) distclean
	cd ./lib/libnetfilter_queue && $(MAKE) distclean
	rm -f *.o *.a nfqttl

nfqttl: $(SRC_FILES)
	$(QUIET_CC)$(CC) $(CFLAGS) -o $@ $(SRC_FILES) $(LIBS)

libmnl:
	cd ./lib/libmnl && ./configure --enable-static && $(MAKE)

libnetlink:
	cd ./lib/libnetlink && $(MAKE)

libnfnetlink:
	cd ./lib/libnfnetlink && ./configure --enable-static && $(MAKE)

libnetfilter_queue:
	cd ./lib/libnetfilter_queue && ./configure --enable-static \
	LIBNFNETLINK_LIBS="-L`pwd | sed  's/\/libnetfilter_queue//'`/libnfnetlink/src/.libs" \
	LIBNFNETLINK_CFLAGS="-I`pwd | sed  's/\/libnetfilter_queue//'`/libnfnetlink/include" \
	LIBMNL_LIBS="-L`pwd | sed  's/\/libnetfilter_queue//'`/libmnl/src/.libs" \
	LIBMNL_CFLAGS="-I`pwd | sed  's/\/libnetfilter_queue//'`/libmnl/include" \
	&& $(MAKE)
