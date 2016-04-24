CFLAGS+=-O2
LIBS+=-lcrypto -lz
DESTDIR="/usr/local"

all: peervpn
peervpn: peervpn.o logging.o
	$(CC) $(LDFLAGS) peervpn.o logging.o $(LIBS) -o $@

peervpn.o: peervpn.c
logging.o: logging.c

install:
	mkdir -p $(DESTDIR)/sbin
	install peervpn $(DESTDIR)/sbin/peervpn
clean:
	rm -f peervpn peervpn.o logging.o
