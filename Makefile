CFLAGS+=-O2 -DDEBUG -g -I ./include
LIBS+=-lcrypto -lz
INC_DIR=./include
DESTDIR="/usr/local"
COMMIT=$(shell git log --format='%H' | head -n 1)

objects = src/encryption/rsa.o \
          src/encryption/crypto.o \
          src/encryption/dh.o \
          src/p2p/auth.o \
          src/p2p/nodeid.o \
          peervpn.o \
          logging.o

all: peervpn
peervpn: $(objects)
	$(CC) $(LDFLAGS) $(objects) $(LIBS) -o $@

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
	rm -f peervpn $(objects)
