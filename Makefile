CFLAGS+=-O2
LIBS+=-lcrypto -lz
ROOT="/usr/local"

all: peervpn
peervpn: peervpn.o
	$(CC) $(LDFLAGS) peervpn.o $(LIBS) -o $@
peervpn.o: peervpn.c

install:
        mkdir -p $(ROOT)/sbin
	install peervpn $(ROOT)/sbin/peervpn
clean:
	rm -f peervpn peervpn.o
