CFLAGS+=-O2
LIBS+=-lcrypto -lz
DESTDIR="/usr/local"

all: peervpn
peervpn: peervpn.o
	$(CC) $(LDFLAGS) peervpn.o $(LIBS) -o $@
peervpn.o: peervpn.c

install:
	mkdir -p $(DESTDIR)/sbin
	install peervpn $(DESTDIR)/sbin/peervpn
clean:
	rm -f peervpn peervpn.o
