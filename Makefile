#	$OpenBSD: Makefile,v 1.1 2018/04/26 13:57:13 eric Exp $

PROG=	filter-dnsbl
MAN=	filter-dnsbl.8
BINDIR=	/usr/libexec/smtpd/
SRCS+=	main.c

CFLAGS+=-Wall -I${.CURDIR}
CFLAGS+=-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=-Wmissing-declarations
CFLAGS+=-Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+=-Wsign-compare
LDADD+=	-levent -lopensmtpd
DPADD=	${LIBEVENT}

.include <bsd.prog.mk>
