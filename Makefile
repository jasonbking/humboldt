ROOT=		$(PWD)
EXTRA_SOURCE=	$(PWD)/../../illumos-extra
OPENSSH_SOURCE=	$(shell echo $(EXTRA_SOURCE)/openssh/openssh*-32)
PROTO_AREA=	$(PWD)/../../../proto
STRAP_AREA=	$(PWD)/../../../proto.strap

CC=		$(STRAP_AREA)/usr/bin/gcc
LD=		/usr/bin/ld
CSTYLE=		$(KERNEL_SOURCE)/usr/src/tools/scripts/cstyle

CFLAGS+=	-gdwarf-2 -I$(PROTO_AREA)/usr/include
CFLAGS64=	-m64 -msave-args
LDFLAGS+=	-L$(PROTO_AREA)/usr/lib

YBENCH_SOURCES=			\
	yubihmac-bench.c
YBENCH_HEADERS=

YBENCH_OBJS=		$(YBENCH_SOURCES:%.c=%.o)

YBENCH_CFLAGS=		-I$(PROTO_AREA)/usr/include/PCSC
YBENCH_LIBS=		-lpcsclite
YBENCH_LDFLAGS=		-L$(PROTO_AREA)/usr/lib

YBENCH_DEPS=		pcsclite


YKTOOL_SOURCES=			\
	yktool.c
YKTOOL_HEADERS=

YKTOOL_OBJS=		$(YKTOOL_SOURCES:%.c=%.o)

YKTOOL_CFLAGS=		-I$(PROTO_AREA)/usr/include/PCSC
YKTOOL_LIBS=		-lpcsclite
YKTOOL_LDFLAGS=		-L$(PROTO_AREA)/usr/lib

YKTOOL_DEPS=		pcsclite


TOKEN_SOURCES=			\
	softtoken_mgr.c		\
	supervisor.c		\
	bunyan.c
TOKEN_HEADERS=			\
	softtoken.h		\
	bunyan.h

TOKEN_OBJS=		$(TOKEN_SOURCES:%.c=%.o)

TOKEN_DEPS=		pcsclite64 libressl

TOKEN_CFLAGS=		$(CFLAGS64) -I$(PROTO_AREA)/usr/include/PCSC -I$(OPENSSH_SOURCE)
TOKEN_LDFLAGS=		-m64 -L$(PROTO_AREA)/usr/lib/amd64
TOKEN_LIBS= 		-lsysevent -lnvpair -lnsl -lsocket -lpcsclite


yubihmac-bench :	CFLAGS+=	$(YBENCH_CFLAGS)
yubihmac-bench :	LIBS+=		$(YBENCH_LIBS)
yubihmac-bench :	LDFLAGS+=	$(YBENCH_LDFLAGS)
yubihmac-bench :	HEADERS=	$(YBENCH_HEADERS)
yubihmac-bench :	DEPS=		$(YBENCH_DEPS:%=deps/%/.ac.install.stamp)

yubihmac-bench: $(YBENCH_OBJS) $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(ALTCTFCONVERT) $@

yktool :		CFLAGS+=	$(YKTOOL_CFLAGS)
yktool :		LIBS+=		$(YKTOOL_LIBS)
yktool :		LDFLAGS+=	$(YKTOOL_LDFLAGS)
yktool :		HEADERS=	$(YKTOOL_HEADERS)
yktool :		DEPS=		$(YKTOOL_DEPS:%=deps/%/.ac.install.stamp)

yktool: $(YKTOOL_OBJS) $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(ALTCTFCONVERT) $@

softtokend :		CFLAGS+=	$(TOKEN_CFLAGS)
softtokend :		LIBS+=		$(TOKEN_LIBS)
softtokend :		LDFLAGS+=	$(TOKEN_LDFLAGS)
softtokend :		HEADERS=	$(TOKEN_HEADERS)
softtokend :		DEPS=		$(TOKEN_DEPS:%=deps/%/.ac.install.stamp)

softtokend: $(TOKEN_OBJS) $(DEPS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	$(ALTCTFCONVERT) $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ -c $<

DEPS_BUILT=				\
	deps/libusb/.ac.all.stamp	\
	deps/libusb64/.ac.all.stamp	\
	deps/pcsclite/.ac.all.stamp	\
	deps/pcsclite64/.ac.all.stamp	\
	deps/ccid/.ac.all.stamp		\
	deps/libressl/.ac.all.stamp

DEPS_INSTALLED=					\
	deps/libusb/.ac.install.stamp		\
	deps/libusb64/.ac.install.stamp		\
	deps/pcsclite/.ac.install.stamp		\
	deps/pcsclite64/.ac.install.stamp	\
	deps/ccid/.ac.install.stamp

LIBUSB_CONFIG_ARGS=		\
	--prefix=/usr		\
	--enable-shared		\
	--disable-static	\
	--disable-timerfd	\
	CFLAGS="$(CFLAGS)"	\
	LDFLAGS="$(LDFLAGS)"	\
	CC=$(CC)

LIBUSB64_CONFIG_ARGS=				\
	--prefix=/usr				\
	--bindir=/usr/bin/amd64			\
	--sbindir=/usr/sbin/amd64		\
	--libdir=/usr/lib/amd64			\
	--enable-shared				\
	--disable-static			\
	--disable-timerfd			\
	CFLAGS="$(CFLAGS) $(CFLAGS64)"		\
	LDFLAGS="$(LDFLAGS) $(CFLAGS64)"	\
	CC=$(CC)

LIBRESSL_CONFIG_ARGS=					\
	--disable-shared				\
	--enable-static					\
	CFLAGS="-gdwarf-2 -msave-args -m64"		\
	LDFLAGS="-L$(PROTO_AREA)/usr/lib/amd64 -m64"	\
	CC=$(CC)

PCSCLITE_CONFIG_ARGS=						\
	--prefix=/usr						\
	--disable-libsystemd					\
	--disable-static					\
	--enable-usbdropdir=/usr/lib/pcsc/drivers		\
	LIBUSB_CFLAGS="-I$(PROTO_AREA)/usr/include/libusb-1.0"	\
	LIBUSB_LIBS="-L$(PROTO_AREA)/usr/lib -lusb-1.0"		\
	CFLAGS="$(CFLAGS)"					\
	LDFLAGS="$(LDFLAGS)"					\
	CC=$(CC)

PCSCLITE64_CONFIG_ARGS=						\
	--prefix=/usr						\
	--bindir=/usr/bin/amd64					\
	--sbindir=/usr/sbin/amd64				\
	--libdir=/usr/lib/amd64					\
	--disable-libsystemd					\
	--disable-static					\
	--enable-usbdropdir=/usr/lib/amd64/pcsc/drivers		\
	LIBUSB_CFLAGS="-I$(PROTO_AREA)/usr/include/libusb-1.0"	\
	LIBUSB_LIBS="-L$(PROTO_AREA)/usr/lib/amd64 -lusb-1.0"	\
	CFLAGS="-gdwarf-2 -msave-args -m64"			\
	LDFLAGS="-L$(PROTO_AREA)/usr/lib/amd64 -m64"		\
	CC=$(CC)

CCID_CONFIG_ARGS=						\
	--prefix=/usr						\
	--enable-usbdropdir=/usr/lib/amd64/pcsc/drivers		\
	PCSC_CFLAGS="-I$(PROTO_AREA)/usr/include/PCSC"		\
	PCSC_LIBS="-L$(PROTO_AREA)/usr/lib/amd64 -lpcsclite"	\
	LIBUSB_CFLAGS="-I$(PROTO_AREA)/usr/include/libusb-1.0"	\
	LIBUSB_LIBS="-L$(PROTO_AREA)/usr/lib/amd64 -lusb-1.0"	\
	CFLAGS="-gdwarf-2 -msave-args -m64"			\
	LDFLAGS="-L$(PROTO_AREA)/usr/lib/amd64 -m64"		\
	CC=$(CC)

deps/pcsclite/.ac.configure.stamp: deps/libusb/.ac.install.stamp
deps/pcsclite64/.ac.configure.stamp: deps/libusb64/.ac.install.stamp
deps/ccid/.ac.configure.stamp: deps/pcsclite64/.ac.install.stamp

deps/libusb/.ac.configure.stamp :	AC_CONFIG_ARGS=$(LIBUSB_CONFIG_ARGS)
deps/libusb64/.ac.configure.stamp : 	AC_CONFIG_ARGS=$(LIBUSB64_CONFIG_ARGS)
deps/pcsclite/.ac.configure.stamp : 	AC_CONFIG_ARGS=$(PCSCLITE_CONFIG_ARGS)
deps/pcsclite64/.ac.configure.stamp : 	AC_CONFIG_ARGS=$(PCSCLITE64_CONFIG_ARGS)
deps/ccid/.ac.configure.stamp :		AC_CONFIG_ARGS=$(CCID_CONFIG_ARGS)
deps/libressl/.ac.configure.stamp :	AC_CONFIG_ARGS=$(LIBRESSL_CONFIG_ARGS)

deps/libusb/.ac.ctf.stamp : 	CTF_TGTS=libusb/.libs/libusb-1.0.so.0.1.0
deps/libusb64/.ac.ctf.stamp : 	CTF_TGTS=libusb/.libs/libusb-1.0.so.0.1.0
deps/pcsclite/.ac.ctf.stamp :	CTF_TGTS=src/pcscd src/.libs/libpcsclite.so.1.0.0
deps/pcsclite64/.ac.ctf.stamp :	CTF_TGTS=src/pcscd src/.libs/libpcsclite.so.1.0.0
deps/ccid/.ac.ctf.stamp :	CTF_TGTS=src/.libs/libccid.so


deps/%/configure.ac: deps/%/.dirstamp
	touch $@

deps/%/.dirstamp: .gitmodules
	git submodule init && \
		git submodule update
	touch $@

deps/%64/.dirstamp: deps/%/.dirstamp
	cd deps && \
		git clone \
		    $(shell basename $(shell dirname $<)) \
		    $(shell basename $(shell dirname $@))
	touch $@

deps/%/configure: deps/%/.dirstamp deps/%/configure.ac
	cd $(shell dirname $<) && \
		git submodule init && git submodule update && \
		autoreconf -fi

deps/%/.ac.configure.stamp: deps/%/.dirstamp deps/%/configure
	cd $(shell dirname $@) && \
		./configure $(AC_CONFIG_ARGS) && \
		touch $(shell basename $@)

deps/%/.ac.all.stamp: deps/%/.dirstamp deps/%/.ac.configure.stamp
	cd $(shell dirname $<) && \
		$(MAKE) -j4
	touch $@

deps/%/.ac.ctf.stamp: deps/%/.dirstamp deps/%/.ac.all.stamp
	cd $(shell dirname $@) && \
		for lib in $(CTF_TGTS); do \
			$(ALTCTFCONVERT) $$lib; \
		done && \
		touch .ac.ctf.stamp

deps/%/.ac.install.stamp: deps/%/.dirstamp deps/%/.ac.ctf.stamp
	cd $(shell dirname $<) && \
		$(MAKE) install DESTDIR=$(PROTO_AREA)
	touch $@

deps/libressl/configure: deps/libressl/.dirstamp deps/libressl/configure.ac
	cd deps/libressl && \
		mkdir -p m4 && \
		bash update.sh && \
		autoreconf -fi
deps/libressl/.ac.install.stamp: deps/libressl/.dirstamp deps/libressl/.ac.all.stamp
	touch $@

world: $(DEPS_BUILT) yubihmac-bench softtokend yktool

install: $(DEPS_INSTALLED) world
	mkdir -p $(DESTDIR)/usr/sbin
	cp yubihmac-bench $(DESTDIR)/usr/sbin
	cp yktool $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/sbin/amd64
	cp softtokend $(DESTDIR)/usr/sbin/amd64
	mkdir -p $(DESTDIR)/lib/svc/manifest/system
	cp pcscd.xml $(DESTDIR)/lib/svc/manifest/system
	mkdir -p $(DESTDIR)/lib/svc/manifest/system/filesystem
	cp unlock-rfd77-zfs.xml $(DESTDIR)/lib/svc/manifest/system/filesystem
	mkdir -p $(DESTDIR)/lib/svc/method
	cp unlock-rfd77-zfs $(DESTDIR)/lib/svc/method
	rm -f $(DESTDIR)/usr/man/man1/pcsc-spy.1

check:
	echo check

clean:
	rm -f *.o yubihmac-bench softtokend yktool
	rm -fr deps

.PHONY: manifest
manifest:
	cp manifest $(DESTDIR)/$(DESTNAME)

mancheck_conf:
	cp mancheck.conf $(DESTDIR)/$(DESTNAME)

