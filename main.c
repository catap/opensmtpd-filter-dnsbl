/*
 * Copyright (c) 2019 Martijn van Duren <martijn@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <event.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <asr.h>

#include "opensmtpd.h"

struct dnsbl_session;

struct dnsbl_query {
	struct event_asr *event;
	int resolved;
	int blacklist;
	struct dnsbl_session *session;
};

struct dnsbl_session {
	int listed;
	int set_header;
	int logged_mark;
	struct dnsbl_query *query;
	struct osmtpd_ctx *ctx;
};

static char **blacklists = NULL;
static size_t nblacklists = 0;
static int markspam = 0;
static int verbose = 0;

void usage(void);
void dnsbl_connect(struct osmtpd_ctx *, const char *,
    struct sockaddr_storage *);
void dnsbl_begin(struct osmtpd_ctx *, uint32_t);
void dnsbl_dataline(struct osmtpd_ctx *, const char *);
void dnsbl_resolve(struct asr_result *, void *);
void dnsbl_session_query_done(struct dnsbl_session *);
void *dnsbl_session_new(struct osmtpd_ctx *);
void dnsbl_session_free(struct osmtpd_ctx *, void *);
void dnsbl_err(const char *, ...);
void dnsbl_errx(const char *, ...);

int
main(int argc, char *argv[])
{
	int ch;
	size_t i;

	while ((ch = getopt(argc, argv, "mv")) != -1) {
		switch (ch) {
		case 'm':
			markspam = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		}
	}

	if (pledge("stdio dns", NULL) == -1)
		dnsbl_err("pledge");

	if ((nblacklists = argc - optind) == 0)
		dnsbl_errx("No blacklist specified");

	if ((blacklists = calloc(nblacklists, sizeof(*blacklists))) == NULL)
		dnsbl_err("malloc");
	for (i = 0; i < nblacklists; i++)
		blacklists[i] = argv[optind + i];

	osmtpd_register_filter_connect(dnsbl_connect);
	osmtpd_local_session(dnsbl_session_new, dnsbl_session_free);
	if (markspam) {
		osmtpd_register_report_begin(1, dnsbl_begin);
		osmtpd_register_filter_dataline(dnsbl_dataline);
	}
	osmtpd_run();

	return 0;
}

void
dnsbl_connect(struct osmtpd_ctx *ctx, const char *hostname,
    struct sockaddr_storage *ss)
{
	struct dnsbl_session *session = ctx->local_session;
	struct asr_query *aq;
	char query[255];
	u_char *addr;
	size_t i;

	if (ss->ss_family == AF_INET)
		addr = (u_char *)(&(((struct sockaddr_in *)ss)->sin_addr));
	else
		addr = (u_char *)(&(((struct sockaddr_in6 *)ss)->sin6_addr));
	for (i = 0; i < nblacklists; i++) {
		if (ss->ss_family == AF_INET) {
			if (snprintf(query, sizeof(query), "%u.%u.%u.%u.%s",
			    addr[3], addr[2], addr[1], addr[0],
			    blacklists[i]) >= (int) sizeof(query))
				dnsbl_errx("Can't create query, domain too long");
		} else if (ss->ss_family == AF_INET6) {
			if (snprintf(query, sizeof(query), "%hhx.%hhx.%hhx.%hhx"
			    ".%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx"
			    ".%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx"
			    ".%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%s",
			    (u_char) (addr[15] & 0xf), (u_char) (addr[15] >> 4),
			    (u_char) (addr[14] & 0xf), (u_char) (addr[14] >> 4),
			    (u_char) (addr[13] & 0xf), (u_char) (addr[13] >> 4),
			    (u_char) (addr[12] & 0xf), (u_char) (addr[12] >> 4),
			    (u_char) (addr[11] & 0xf), (u_char) (addr[11] >> 4),
			    (u_char) (addr[10] & 0xf), (u_char) (addr[10] >> 4),
			    (u_char) (addr[9] & 0xf), (u_char) (addr[9] >> 4),
			    (u_char) (addr[8] & 0xf), (u_char) (addr[8] >> 4),
			    (u_char) (addr[7] & 0xf), (u_char) (addr[8] >> 4),
			    (u_char) (addr[6] & 0xf), (u_char) (addr[7] >> 4),
			    (u_char) (addr[5] & 0xf), (u_char) (addr[5] >> 4),
			    (u_char) (addr[4] & 0xf), (u_char) (addr[4] >> 4),
			    (u_char) (addr[3] & 0xf), (u_char) (addr[3] >> 4),
			    (u_char) (addr[2] & 0xf), (u_char) (addr[2] >> 4),
			    (u_char) (addr[1] & 0xf), (u_char) (addr[1] >> 4),
			    (u_char) (addr[0] & 0xf), (u_char) (addr[0] >> 4),
			    blacklists[i]) >= (int) sizeof(query))
				dnsbl_errx("Can't create query, domain too long");
		} else
			dnsbl_errx("Invalid address family received");

		aq = gethostbyname_async(query, NULL);
		session->query[i].event = event_asr_run(aq, dnsbl_resolve,
		    &(session->query[i]));
		session->query[i].blacklist = i;
		session->query[i].session = session;
	}
}

void
dnsbl_resolve(struct asr_result *result, void *arg)
{
	struct dnsbl_query *query = arg;
	struct dnsbl_session *session = query->session;
	size_t i;

	query->resolved = 1;
	query->event = NULL;
	if (result->ar_hostent != NULL) {
		if (!markspam) {
			osmtpd_filter_disconnect(session->ctx, "Listed at %s",
			    blacklists[query->blacklist]);
			fprintf(stderr, "%016"PRIx64" listed at %s: rejected\n",
			    session->ctx->reqid, blacklists[query->blacklist]);
		} else {
			dnsbl_session_query_done(session);
			session->listed = query->blacklist;
			osmtpd_filter_proceed(session->ctx);
			/* Delay logging until we have a message */
		}
		return;
	}
	if (result->ar_h_errno != HOST_NOT_FOUND) {
		osmtpd_filter_disconnect(session->ctx, "DNS error on %s",
		    blacklists[query->blacklist]);
		return;
	}

	for (i = 0; i < nblacklists; i++) {
		if (!session->query[i].resolved)
			return;
	}
	osmtpd_filter_proceed(session->ctx);
	if (verbose)
		fprintf(stderr, "%016"PRIx64" not listed\n",
		    session->ctx->reqid);
}

void
dnsbl_begin(struct osmtpd_ctx *ctx, uint32_t msgid)
{
	struct dnsbl_session *session = ctx->local_session;

	if (session->listed != -1) {
		if (!session->logged_mark) {
			fprintf(stderr, "%016"PRIx64" listed at %s: Marking as "
			    "spam\n", ctx->reqid, blacklists[session->listed]);
			session->logged_mark = 1;
		}
		session->set_header = 1;
	}
}

void
dnsbl_dataline(struct osmtpd_ctx *ctx, const char *line)
{
	struct dnsbl_session *session = ctx->local_session;

	if (session->set_header) {
		osmtpd_filter_dataline(ctx, "X-Spam: yes");
		osmtpd_filter_dataline(ctx, "X-Spam-DNSBL: Listed at %s",
		    blacklists[session->listed]);
		session->set_header = 0;
		
	}
	osmtpd_filter_dataline(ctx, "%s", line);
}

void
dnsbl_session_query_done(struct dnsbl_session *session)
{
	size_t i;

	for (i = 0; i < nblacklists; i++) {
		if (!session->query[i].resolved) {
			event_asr_abort(session->query[i].event);
			session->query[i].resolved = 1;
		}
	}
}

void *
dnsbl_session_new(struct osmtpd_ctx *ctx)
{
	struct dnsbl_session *session;

	if ((session = calloc(1, sizeof(*session))) == NULL)
		dnsbl_err("malloc");
	if ((session->query = calloc(nblacklists, sizeof(*(session->query))))
	    == NULL)
		dnsbl_err("malloc");
	session->listed = -1;
	session->set_header = 0;
	session->logged_mark = 0;
	session->ctx = ctx;

	return session;
}

void
dnsbl_session_free(struct osmtpd_ctx *ctx, void *data)
{
	struct dnsbl_session *session = data;

	dnsbl_session_query_done(session);
	free(session->query);
	free(session);
}

void
dnsbl_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "%s\n", strerror(errno));
	va_end(ap);
	exit(1);
}

void
dnsbl_errx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	exit(1);
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-m] blacklist [...]\n",
	    getprogname());
	exit(1);
}
