/*
 * Copyright (c) 2023-2024 Kirill A. Korinsky <kirill@korins.ky>
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
#include <limits.h>
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
	int running;
	int blacklist;
	int listed;
	int error;
	struct dnsbl_session *session;
};

struct dnsbl_session {
	int set_header;
	int logged_mark;
	int inheader;
	int headers_done;
	int running_queries;
	struct dnsbl_query *query;
	struct osmtpd_ctx *ctx;
};

static int *iswhites;
static int *isdomain;
static long *scores;
static const char **exptected;
static const char **blacklists = NULL;
static const char **printblacklists;
static size_t nblacklists = 0;
static int markspam = 0;
static int verbose = 0;

const char *dnsbl_printblacklist(const char *);
void dnsbl_connect(struct osmtpd_ctx *, const char *,
	struct sockaddr_storage *);
void dnsbl_begin(struct osmtpd_ctx *, uint32_t);
void dnsbl_dataline(struct osmtpd_ctx *, const char *);
void dnsbl_resolve(struct asr_result *, void *);
void dnsbl_session_query_done(struct dnsbl_session *);
void *dnsbl_session_new(struct osmtpd_ctx *);
void dnsbl_session_free(struct osmtpd_ctx *, void *);
void usage(void);

int
main(int argc, char *argv[])
{
	int     ch, w, d;
	long    s;
	char   *ep;
	size_t  i, j, records;

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
		osmtpd_err(1, "pledge");

	if ((records = argc - optind) == 0)
		osmtpd_errx(1, "No blacklist specified");

	for (i = 0; i < records; i++) {
		if (strcmp(argv[optind + i], "-w") == 0) {
			if (!markspam)
				osmtpd_errx(1, "White lists requires -m");
			continue;
		}
		if (strcmp(argv[optind + i], "-d") == 0)
			continue;
		if (strcmp(argv[optind + i], "-e") == 0) {
			i++;
			continue;
		}
		if (strcmp(argv[optind + i], "-s") == 0) {
			i++;
			continue;
		}
		nblacklists++;
	}

	scores = calloc(nblacklists, sizeof(long));
	iswhites = calloc(nblacklists, sizeof(int));
	isdomain = calloc(nblacklists, sizeof(int));
	exptected = calloc(nblacklists, sizeof(*exptected));
	blacklists = calloc(nblacklists, sizeof(*blacklists));
	printblacklists = calloc(nblacklists, sizeof(*printblacklists));
	if (scores == NULL || iswhites == NULL || isdomain == NULL ||
		printblacklists == NULL || blacklists == NULL)
		osmtpd_err(1, "malloc");
	for (i = 0, j = 0, w = 0, d = 0, s = LONG_MIN; i < records; i++) {
		if (w == 0 && strcmp(argv[optind + i], "-w") == 0) {
			w = 1;
			continue;
		}
		if (d == 0 && strcmp(argv[optind + i], "-d") == 0) {
			d = 1;
			continue;
		}
		if (strcmp(argv[optind + i], "-e") == 0) {
			i++;
			if (i < records)
				exptected[j] = argv[optind + i];
			continue;
		}
		if (strcmp(argv[optind + i], "-s") == 0) {
			i++;
			if (i >= records)
				continue;
			errno = 0;
			s = strtol(argv[optind + i], &ep, 10);
			if (*argv[optind + i] == '\0' || *ep != '\0' ||
				(errno == ERANGE && (s == LONG_MIN || s == LONG_MAX)))
				osmtpd_errx(1, "Invalid score: %s", argv[optind + i]);
			continue;
		}
		if (s == LONG_MIN && w)
			scores[j] = nblacklists;
		else if (s == LONG_MIN)
			scores[j] = 1;
		else
			scores[j] = s;
		iswhites[j] = w;
		isdomain[j] = d;
		blacklists[j] = argv[optind + i];
		printblacklists[j] = dnsbl_printblacklist(argv[optind + i]);

		if (verbose)
			fprintf(stderr, "Added list %s with score %ld as %s%s\n",
				printblacklists[j], scores[j],
				iswhites[j] ? "white " : "",
				isdomain[j] ? "domain" : "IP");

		w = 0;
		d = 0;
		s = LONG_MIN;
		j++;
	}

	osmtpd_register_filter_connect(dnsbl_connect);
	osmtpd_local_session(dnsbl_session_new, dnsbl_session_free);
	if (markspam) {
		osmtpd_register_report_begin(1, dnsbl_begin);
		osmtpd_register_filter_dataline(dnsbl_dataline);
	}
	osmtpd_run();

	return 0;
}

const char *
dnsbl_printblacklist(const char *blacklist)
{
	/* All of abusix is paid and has a key in the first spot */
	if (strcasestr(blacklist, ".mail.abusix.zone") != NULL)
		return strchr(blacklist, '.') + 1;
	/* XXX assume dq.spamhaus.net is paid and has a key in the first spot */
	if (strcasestr(blacklist, ".dq.spamhaus.net") != NULL)
		return strchr(blacklist, '.') + 1;
	return blacklist;
}

void
dnsbl_connect(struct osmtpd_ctx *ctx, const char *rdns,
	struct sockaddr_storage *ss)
{
	struct dnsbl_session *session = ctx->local_session;
	struct asr_query *aq;
	char query[HOST_NAME_MAX + 1];
	u_char *addr;
	size_t i;

	if (ss->ss_family == AF_INET)
		addr = (u_char *)(&(((struct sockaddr_in *)ss)->sin_addr));
	else
		addr = (u_char *)(&(((struct sockaddr_in6 *)ss)->sin6_addr));
	for (i = 0; i < nblacklists; i++) {
		if (isdomain[i]) {
			if (rdns == NULL || *rdns == '\0'
				|| strcmp(rdns, "<unknown>") == 0)
				continue;
			if (snprintf(query, sizeof(query), "%s.%s.",
				rdns, blacklists[i]) >= (int) sizeof(query))
				osmtpd_errx(1,
					"Can't create query, domain too long");
		} else if (ss->ss_family == AF_INET) {
			if (snprintf(query, sizeof(query), "%u.%u.%u.%u.%s.",
				addr[3], addr[2], addr[1], addr[0],
				blacklists[i]) >= (int) sizeof(query))
				osmtpd_errx(1,
					"Can't create query, domain too long");
		} else if (ss->ss_family == AF_INET6) {
			if (snprintf(query, sizeof(query), "%hhx.%hhx.%hhx.%hhx"
				".%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx"
				".%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx"
				".%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%s.",
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
				osmtpd_errx(1,
					"Can't create query, domain too long");
		} else
			osmtpd_errx(1, "Invalid address family received");

		aq = gethostbyname_async(query, NULL);
		session->query[i].event = event_asr_run(aq, dnsbl_resolve,
			&(session->query[i]));
		if (session->query[i].event == NULL)
			osmtpd_errx(1, "Can't run DNS query");
		session->query[i].blacklist = i;
		session->query[i].listed = 0;
		session->query[i].error = 0;
		session->query[i].session = session;
		session->query[i].running = 1;
		session->running_queries++;
	}
}

void
dnsbl_resolve(struct asr_result *result, void *arg)
{
	struct in_addr *addr_name;
	struct dnsbl_query *query = arg;
	struct dnsbl_session *session = query->session;
	size_t i, found;

	if (query->running == 0 || query->session->running_queries == 0)
		return;

	query->session->running_queries--;
	query->running = 0;
	query->event = NULL;
	if (result->ar_hostent != NULL) {
		if (exptected[query->blacklist] != NULL) {
			found = 0;

			if (result->ar_hostent->h_addrtype != AF_INET)
				goto bypass;

			for (i = 0; result->ar_hostent->h_addr_list[i]; i++) {
				addr_name =
					(struct in_addr *)result->ar_hostent->h_addr_list[i];
				if (strcasecmp(
						exptected[query->blacklist],
						inet_ntoa(*addr_name))
					== 0) {
					found = 1;
					break;
				}
			}

			if (!found)
				goto bypass;
		}
		if (!markspam) {
			osmtpd_filter_disconnect(session->ctx, "%s listed at %s",
				isdomain[query->blacklist] ? "Domain" : "IP",
				printblacklists[query->blacklist]);
			fprintf(stderr, "%016"PRIx64" %s listed at %s: rejected\n",
				session->ctx->reqid,
				isdomain[query->blacklist] ? "omain" : "IP",
				printblacklists[query->blacklist]);
			dnsbl_session_query_done(session);
			return;
		}
		if (verbose)
			fprintf(stderr, "%016"PRIx64" %s listed at %s\n",
				session->ctx->reqid,
				isdomain[query->blacklist] ? "Domain" : "IP",
				printblacklists[query->blacklist]);
		query->listed = 1;
	} else if (result->ar_h_errno != HOST_NOT_FOUND
		&& result->ar_h_errno != NO_DATA
		&& result->ar_h_errno != NO_ADDRESS) {

		if (result->ar_h_errno == NETDB_INTERNAL)
			fprintf(stderr, "%016"PRIx64" DNS error on %s (%s): %s\n",
				session->ctx->reqid,
				printblacklists[query->blacklist],
				isdomain[query->blacklist] ? "Domain" : "IP",
				strerror(result->ar_errno));

		if (!markspam) {
			osmtpd_filter_disconnect(session->ctx, "DNS error on %s",
				printblacklists[query->blacklist]);
			dnsbl_session_query_done(session);
			return;
		}

		if (result->ar_h_errno != NETDB_INTERNAL)
			fprintf(stderr, "%016"PRIx64" DNS error on %s (%s): %s\n",
				session->ctx->reqid,
				printblacklists[query->blacklist],
				isdomain[query->blacklist] ? "Domain" : "IP",
				hstrerror(result->ar_h_errno));
		query->error = 1;
	}

bypass:
	if (query->session->running_queries > 0)
		return;

	dnsbl_session_query_done(session);
	osmtpd_filter_proceed(session->ctx);

	if (verbose)
		fprintf(stderr, "%016"PRIx64" %s %slisted on %s\n",
			session->ctx->reqid,
			isdomain[query->blacklist] ? "Domain" : "IP",
			query->listed ? "" : "not ",
			printblacklists[query->blacklist]);
}

void
dnsbl_begin(struct osmtpd_ctx *ctx, uint32_t msgid)
{
	size_t i;
	struct dnsbl_session *session = ctx->local_session;
	int logged_mark = session->logged_mark;

	for (i = 0; i < nblacklists; i++) {
		if (session->query[i].listed) {
			if (!session->logged_mark) {
				if (verbose)
					fprintf(stderr, "%016"PRIx64" %s listed at %s:"
							" Marking as spam\n",
							ctx->reqid,
							isdomain[session->query->blacklist] ? "Domain" : "IP",
							printblacklists[session->query[i].blacklist]);
				logged_mark = 1;
			}
			session->set_header = 1;
		} else if (session->query[i].error) {
			session->set_header = 1;
		}
	}

	session->logged_mark = logged_mark;
}

void
dnsbl_dataline(struct osmtpd_ctx *ctx, const char *line)
{
	long score = 0, pscore = 0;
	size_t i, j;
	struct dnsbl_session *session = ctx->local_session;

	if (session->set_header) {
		for (i = 0; i < nblacklists; i++) {
			j = session->query[i].blacklist;
			if (session->query[i].error) {
				osmtpd_filter_dataline(ctx,
					"X-Spam-DNS: Error at %s (%s)",
					printblacklists[j],
					isdomain[j] ? "Domain" : "IP");
				if (iswhites[j])
					pscore -= scores[j];
				else
					pscore += scores[j];
				continue;
			}
			if (!session->query[i].listed)
				continue;
			if (iswhites[j]) {
				score -= scores[j];
				pscore -= scores[j];
				osmtpd_filter_dataline(ctx,
					"X-Spam-DNSWL: %s listed at %s",
					isdomain[j] ? "Domain" : "IP",
					printblacklists[j]);
			} else {
				score += scores[j];
				pscore += scores[j];
				osmtpd_filter_dataline(ctx,
					"X-Spam-DNSBL: %s listed at %s",
					isdomain[j] ? "Domain" : "IP",
					printblacklists[j]);
			}
		}
		osmtpd_filter_dataline(ctx, "X-Spam-Score: %ld", score);
		if (score != pscore)
			osmtpd_filter_dataline(ctx, "X-Spam-PScore: %ld", pscore);
		if ((score > 0 && pscore <= 0) || (score <= 0 && pscore > 0))
			osmtpd_filter_dataline(ctx, "X-Spam: Unknown");
		else if (score > 0)
			osmtpd_filter_dataline(ctx, "X-Spam: Yes");
		session->set_header = 0;
	}

	if (line[0] == '\0')
		session->headers_done = 1;

	if (!session->headers_done) {
		if (line[0] != ' ' && line[0] != '\t')
			session->inheader = 0;

		if (session->inheader && (line[0] == ' ' || line[0] == '\t'))
			return;
		else if (strncasecmp(line, "X-Spam", 6) == 0) {
			session->inheader = 1;
			return;
		}
	}

	osmtpd_filter_dataline(ctx, "%s", line);
}

void
dnsbl_session_query_done(struct dnsbl_session *session)
{
	size_t i;

	session->running_queries = 0;

	for (i = 0; i < nblacklists; i++) {
		if (session->query[i].running) {
			session->query[i].running = 0;
			event_asr_abort(session->query[i].event);
		}
	}
}

void *
dnsbl_session_new(struct osmtpd_ctx *ctx)
{
	struct dnsbl_session *session;

	if ((session = calloc(1, sizeof(*session))) == NULL)
		osmtpd_err(1, "malloc");
	if ((session->query = calloc(nblacklists, sizeof(*(session->query))))
		== NULL)
		osmtpd_err(1, "malloc");
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

__dead void
usage(void)
{
	fprintf(stderr,
		"usage: filter-dnsbl [-mv] [[-w] [-d] [-e IP] [-s score] list]+\n");
	exit(1);
}
