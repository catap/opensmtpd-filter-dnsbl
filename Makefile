#	$OpenBSD: Makefile,v 1.1 2018/04/26 13:57:13 eric Exp $

PROG=	filter-dnsbl
BINDIR=	/usr/libexec/smtpd/
SRCS+=	main.c log.c smtp_proc.c

CFLAGS+= -g3 -O0
LDADD+=	-levent
DPADD=	${LIBEVENT}

.include <bsd.prog.mk>
