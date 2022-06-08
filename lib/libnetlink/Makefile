.PHONY: all clean install uninstall
CFLAGS := -g0 -Wall -std=c11
CFLAGS += -DHAVE_LIBMNL
CFLAGS += -I./include/uapi -I./include -I../libmnl/include
SRC_FILES = libnetlink.c

all: libnetlink.a

clean: 
	rm -f *.o *.a

libnetlink.a: libnetlink.o
	$(AR) rcs $@ $^

libnetlink.o: $(SRC_FILES)
	$(CC) $(CFLAGS) -c -o $@ $^