ROOT=		$(PWD)
EXTRA_SOURCE=	$(PWD)/../../illumos-extra
OPENSSH_SOURCE=	$(shell echo $(EXTRA_SOURCE)/openssh/openssh*-32)
PROTO_AREA=	$(PWD)/../../../proto
STRAP_AREA=	$(PWD)/../../../proto.strap
DEPS=		$(ROOT)/deps

CC=		$(STRAP_AREA)/usr/bin/gcc
LD=		/usr/bin/ld
CSTYLE=		$(KERNEL_SOURCE)/usr/src/tools/scripts/cstyle

BASE_CFLAGS=	-gdwarf-2 -isystem $(PROTO_AREA)/usr/include -Wall
CFLAGS+=	$(BASE_CFLAGS)
CFLAGS64=	-m64 -msave-args -Wall
LDFLAGS+=	-L$(PROTO_AREA)/usr/lib

#
# Conditional logic to allow one to toggle between pcsc and the platform
# implementation.
#
PRE_POUND=		pre\#
POUND_SIGN=		$(PRE_POUND:pre\%=%)

USE_PCSCLITE=
USE_SYSTEM_PCSC=			$(POUND_SIGN)
#
# Uncomment the next line _only_ to use the system PCSC implementation.
#
#USE_SYSTEM_PCSC=
$(USE_SYSTEM_PCSC)USE_PCSCLITE=		$(POUND_SIGN)

$(USE_PCSCLITE)PCSC_CFLAGS=		-I$(PROTO_AREA)/usr/include/PCSC
$(USE_PCSCLITE)PCSC_LDLIBS=		-lpcsclite
$(USE_PCSCLITE)PCSC_DEPS=		pcsclite
$(USE_PCSCLITE)PCSC_DEPS64=		pcsclite64
$(USE_PCSCLITE)PCSC_MANIFEST_FLAGS=	-DUSE_PCSCLITE

$(USE_SYSTEM_PCSC)PCSC_CFLAGS=
$(USE_SYSTEM_PCSC)PCSC_LDLIBS=		-lpcsc
$(USE_SYSTEM_PCSC)PCSC_DEPS=
$(USE_SYSTEM_PCSC)PCSC_DEPS64=
$(USE_SYSTEM_PCSC)PCSC_MANIFEST_FLAGS=	-DUSE_SYSTEM_PCSC


YKTOOL_SOURCES=			\
	yktool.c
YKTOOL_HEADERS=

YKTOOL_OBJS=		$(YKTOOL_SOURCES:%.c=%.o)

YKTOOL_CFLAGS=		$(PCSC_CFLAGS)
YKTOOL_LIBS=		$(PCSC_LDLIBS) -lumem
YKTOOL_LDFLAGS=		-L$(PROTO_AREA)/usr/lib

YKTOOL_DEPS=		$(PCSC_DEPDS)


_ED25519_SOURCES=		\
	ed25519.c		\
	fe25519.c		\
	ge25519.c		\
	sc25519.c		\
	hash.c			\
	blocks.c
ED25519_SOURCES=$(_ED25519_SOURCES:%=ed25519/%)

_CHAPOLY_SOURCES=		\
	chacha.c		\
	poly1305.c
CHAPOLY_SOURCES=$(_CHAPOLY_SOURCES:%=chapoly/%)

_LIBSSH_SOURCES=		\
	sshbuf.c		\
	sshkey.c		\
	ssh-ed25519.c		\
	ssh-ecdsa.c		\
	ssh-rsa.c		\
	cipher.c		\
	digest-openssl.c	\
	bcrypt-pbkdf.c		\
	blowfish.c		\
	rsa.c			\
	base64.c		\
	atomicio.c		\
	authfd.c
LIBSSH_SOURCES=				\
	$(_LIBSSH_SOURCES:%=libssh/%)	\
	$(ED25519_SOURCES)		\
	$(CHAPOLY_SOURCES)

TOKEN_SOURCES=			\
	softtoken_mgr.c		\
	supervisor.c		\
	bunyan.c		\
	agent.c			\
	piv.c			\
	tlv.c			\
	ykccid.c		\
	custr.c			\
	json.c			\
	$(LIBSSH_SOURCES)
TOKEN_HEADERS=			\
	softtoken.h		\
	bunyan.h		\
	piv.h			\
	custr.h			\
	json.h			\
	tlv.h

TOKEN_OBJS=		$(TOKEN_SOURCES:%.c=%.o)

TOKEN_DEPS=		$(PCSC_DEPS64) libressl

TOKEN_CFLAGS=		$(PCSC_CFLAGS) \
			-I$(DEPS)/libressl/include/ \
			-fstack-protector-all \
			-D_REENTRANT \
			$(BASE_CFLAGS) $(CFLAGS64)
TOKEN_LDFLAGS=		-m64 -L$(PROTO_AREA)/usr/lib/amd64 \
			-Wl,-z -Wl,aslr \
			-D_REENTRANT
TOKEN_LIBS= 		-lsysevent -lnvpair -lnsl -lsocket $(PCSC_LDLIBS) \
			-lssp -lumem -lrename -lz \
			$(DEPS)/libressl/crypto/.libs/libcrypto.a

GOSSIP_SOURCES=			\
	gossip.c		\
	trustchain.c		\
	bunyan.c		\
	piv.c			\
	tlv.c			\
	custr.c			\
	json.c			\
	$(LIBSSH_SOURCES)
GOSSIP_HEADERS=			\
	trustchain.h		\
	bunyan.h		\
	piv.h			\
	custr.h			\
	json.h			\
	tlv.h

GOSSIP_OBJS=		$(GOSSIP_SOURCES:%.c=%.o)

GOSSIP_DEPS=		$(PCSC_DEPS64) libressl

GOSSIP_CFLAGS=		$(PCSC_CFLAGS) \
			-I$(DEPS)/libressl/include/ \
			-fstack-protector-all \
			-D_REENTRANT \
			$(BASE_CFLAGS) $(CFLAGS64)
GOSSIP_LDFLAGS=		-m64 -L$(PROTO_AREA)/usr/lib/amd64 \
			-Wl,-z -Wl,aslr \
			-D_REENTRANT
GOSSIP_LIBS= 		-lnvpair -lnsl -lsocket $(PCSC_LDLIBS) \
			-lssp -lumem -lrename -lz \
			$(DEPS)/libressl/crypto/.libs/libcrypto.a


PIVTOOL_SOURCES=		\
	pivtool.c		\
	tlv.c			\
	piv.c			\
	bunyan.c		\
	json.c			\
	custr.c			\
	$(LIBSSH_SOURCES)
PIVTOOL_HEADERS=		\
	tlv.h			\
	bunyan.h		\
	piv.h
PIVTOOL_OBJS=		$(PIVTOOL_SOURCES:%.c=%.o)
PIVTOOL_DEPS=		$(PCSC_DEPS64) libressl
PIVTOOL_CFLAGS=		$(PCSC_CFLAGS) \
			-I$(DEPS)/libressl/include/ \
			-fstack-protector-all \
			-D_REENTRANT \
			$(BASE_CFLAGS) $(CFLAGS64)
PIVTOOL_LDFLAGS=		-m64 -L$(PROTO_AREA)/usr/lib/amd64 \
			-Wl,-z -Wl,aslr \
			-D_REENTRANT
PIVTOOL_LIBS= 		$(PCSC_LDLIBS) -lssp -lumem -lnvpair -lz \
			$(DEPS)/libressl/crypto/.libs/libcrypto.a

yktool :		CFLAGS+=	$(YKTOOL_CFLAGS)
yktool :		LIBS+=		$(YKTOOL_LIBS)
yktool :		LDFLAGS+=	$(YKTOOL_LDFLAGS)
yktool :		HEADERS=	$(YKTOOL_HEADERS)

$(YKTOOL_DEPS): $(YKTOOL_DEPS:%=deps/%/.ac.install.stamp)

yktool: $(YKTOOL_OBJS) $(YKTOOL_DEPS:%=deps/%/.ac.install.stamp)
	$(CC) $(LDFLAGS) -o $@ $(YKTOOL_OBJS) $(LIBS)
	$(ALTCTFCONVERT) $@

softtokend :		CFLAGS=		$(TOKEN_CFLAGS)
softtokend :		LIBS+=		$(TOKEN_LIBS)
softtokend :		LDFLAGS+=	$(TOKEN_LDFLAGS)
softtokend :		HEADERS=	$(TOKEN_HEADERS)

$(TOKEN_OBJS):	$(TOKEN_DEPS:%=deps/%/.ac.install.stamp)

softtokend: $(TOKEN_OBJS) $(TOKEN_DEPS:%=deps/%/.ac.install.stamp)
	$(CC) $(LDFLAGS) -o $@ $(TOKEN_OBJS) $(LIBS)
	$(ALTCTFCONVERT) $@

pivtool :		CFLAGS=		$(PIVTOOL_CFLAGS)
pivtool :		LIBS+=		$(PIVTOOL_LIBS)
pivtool :		LDFLAGS+=	$(PIVTOOL_LDFLAGS)
pivtool :		HEADERS=	$(PIVTOOL_HEADERS)

$(PIVTOOL_OBJS): $(PIVTOOL_DEPS:%=deps/%/.ac.install.stamp)

pivtool: $(PIVTOOL_OBJS) $(PIVTOOL_DEPS:%=deps/%/.ac.install.stamp)
	$(CC) $(LDFLAGS) -o $@ $(PIVTOOL_OBJS) $(LIBS)
	$(ALTCTFCONVERT) $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -o $@ -c $<

$(USE_PCSCLITE)DEPS_BUILT=				\
	deps/libusb/.ac.all.stamp	\
	deps/libusb64/.ac.all.stamp	\
	deps/pcsclite/.ac.all.stamp	\
	deps/pcsclite64/.ac.all.stamp	\
	deps/ccid/.ac.all.stamp		\
	deps/libressl/.ac.all.stamp
$(USE_SYSTEM_PCSC)DEPS_BUILT=		\
	deps/libressl/.ac.all.stamp

$(USE_PCSCLITE)DEPS_INSTALLED=					\
	deps/libusb/.ac.install.stamp		\
	deps/libusb64/.ac.install.stamp		\
	deps/pcsclite/.ac.install.stamp		\
	deps/pcsclite64/.ac.install.stamp	\
	deps/ccid/.ac.install.stamp
$(USE_SYSTEM_PCSC)DEPS_INSTALLED=

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

world: $(DEPS_BUILT) softtokend yktool pivtool

install: $(DEPS_INSTALLED) world
	mkdir -p $(DESTDIR)/usr/sbin
	cp yktool $(DESTDIR)/usr/sbin
	cp rfd77-zpool-create $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/sbin/amd64
	cp pivtool $(DESTDIR)/usr/sbin/amd64
	ln -sf amd64/pivtool $(DESTDIR)/usr/sbin/pivtool
	mkdir -p $(DESTDIR)/lib/svc/manifest/system
	cp pcscd.xml $(DESTDIR)/lib/svc/manifest/system
	cp soft-token.xml $(DESTDIR)/lib/svc/manifest/system
	cp piv-system-token.xml $(DESTDIR)/lib/svc/manifest/system
	mkdir -p $(DESTDIR)/lib/svc/manifest/system/filesystem
	cp unlock-rfd77-zfs.xml $(DESTDIR)/lib/svc/manifest/system/filesystem
	mkdir -p $(DESTDIR)/lib/svc/method
	cp unlock-rfd77-zfs $(DESTDIR)/lib/svc/method
	cp piv-system-token $(DESTDIR)/lib/svc/method
	cp system-pcscd $(DESTDIR)/lib/svc/method
	cp system-soft-token $(DESTDIR)/lib/svc/method
	mkdir -p $(DESTDIR)/smartdc/bin
	cp softtokend $(DESTDIR)/smartdc/bin
	mkdir -p $(DESTDIR)/smartdc/lib
	cp piv-prompt-pin.sh $(DESTDIR)/smartdc/lib
	rm -f $(DESTDIR)/usr/man/man1/pcsc-spy.1

check:
	echo check

clean:
	rm -f *.o softtokend yktool pivtool
	rm -fr deps

.PHONY: manifest
manifest:
	cpp $@ $(PCSC_MANIFEST_FLAGS) > $(DESTDIR)/$(DESTNAME)

mancheck_conf:
	cp mancheck.conf $(DESTDIR)/$(DESTNAME)

cscope:
	find . -type f -name '*.[chs]' > cscope.files'
	cscope-fast -bq
