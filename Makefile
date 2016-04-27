CFLAGS+=-O2 -DSECCOMP_ENABLE -g
LIBS+=-lcrypto -lz -lseccomp 
DESTDIR="/usr/local"
COMMIT=$(shell git log --format='%H' | head -n 1)

all: peervpn
peervpn: peervpn.o logging.o
	$(CC) $(LDFLAGS) peervpn.o logging.o $(LIBS) -o $@

peervpn.o: peervpn.c
logging.o: logging.c

rpm:
	echo "Building RPM for $(COMMIT)"
	mkdir -p redhat/build/SPECS
	mkdir -p redhat/build/SRPCS
	mkdir -p redhat/build/SOURCES
	mkdir -p redhat/build/BUILD
	mkdir -p redhat/build/BUILDROOT
	cp redhat/peervpn.spec redhat/build/SPECS
	sed -i 's/CURRENT_COMMIT/$(COMMIT)/g' redhat/build/SPECS/peervpn.spec
	cd redhat/build/SOURCES && spectool -g ../SPECS/peervpn.spec && cd .. && rpmbuild --define "_topdir `pwd`" -ba SPECS/peervpn.spec
install:
	mkdir -p $(DESTDIR)/sbin
	install peervpn $(DESTDIR)/sbin/peervpn
clean:
	rm -f peervpn peervpn.o logging.o
