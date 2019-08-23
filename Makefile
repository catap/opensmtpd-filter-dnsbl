PROG=	filter-dnsbl
MAN=	filter-dnsbl.8
BINDIR=	${LOCALBASE}/libexec/smtpd/
MANDIR=	${LOCALBASE}/man/man

SRCS+=	main.c

CFLAGS+=-Wall -I${.CURDIR}
CFLAGS+=-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations
CFLAGS+=-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare
LDADD+=	-levent -lopensmtpd
DPADD=	${LIBEVENT}

bindir:
	${INSTALL} -d ${DESTDIR}${BINDIR}

.include <bsd.prog.mk>
