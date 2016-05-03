CFLAGS+=-O2 -g -DSECCOMP_ENABLE -DDEBUG -I ./include
LIBS+=-lcrypto -lz -lseccomp
INC_DIR=./include
DESTDIR="/usr/local"
COMMIT=$(shell git log --format='%H' | head -n 1)

objects = src/encryption/rsa.o \
          src/encryption/crypto.o \
          src/encryption/dh.o \
          src/p2p/idsp.o \
          src/p2p/auth.o \
          src/p2p/nodeid.o \
          src/p2p/nodedb.o \
          src/p2p/peeraddr.o \
          src/p2p/peermgt.o \
          src/p2p/authmgt.o \
          src/p2p/packet.o \
          src/p2p/dfrag.o \
          src/p2p/p2psec.o \
          src/p2p/netid.o \
          src/p2p/seq.o \
          src/platform/io.o \
          src/platform/seccomp.o \
          src/platform/perms.o \
          src/app/init.o \
          src/app/loop.o \
          src/app/config.o \
          src/app/util.o \
          src/app/map.o \
          src/app/logging.o \
          src/ethernet/checksum.o \
          src/ethernet/ndp6.o \
          src/ethernet/switch.o \
          src/ethernet/virtserv.o \
          peervpn.o \

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
