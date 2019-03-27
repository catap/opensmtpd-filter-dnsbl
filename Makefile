#	$OpenBSD: Makefile,v 1.1 2018/04/26 13:57:13 eric Exp $

PROG=	dnsbl
BINDIR=	/usr/bin
SRCS+=	main.c smtp_proc.c

.include <bsd.prog.mk>
