#include <sys/tree.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <asr.h>

#include "smtp_proc.h"

struct dnsbl_session;

struct dnsbl_query {
	struct asr_query *query;
	struct event_asr *event;
	struct event timeout;
	int resolved;
	int blacklist;
	struct dnsbl_session *session;
};

struct dnsbl_session {
	uint64_t reqid;
	uint64_t token;
	struct dnsbl_query *query;
	RB_ENTRY(dnsbl_session) entry;
};

RB_HEAD(dnsbl_sessions, dnsbl_session) dnsbl_sessions = RB_INITIALIZER(NULL);
RB_PROTOTYPE(dnsbl_sessions, dnsbl_session, entry, dnsbl_session_cmp);

static char **blacklists = NULL;
static size_t nblacklists = 0;

void usage(void);
void dnsbl_connect(char *, int, struct timespec *, char *, char *, uint64_t,
    uint64_t, char *, struct inx_addr *);
void dnsbl_disconnect(char *, int, struct timespec *, char *, char *, uint64_t);
void dnsbl_resolve(struct asr_result *, void *);
void dnsbl_timeout(int, short, void *);
void dnsbl_session_free(struct dnsbl_session *);
int dnsbl_session_cmp(struct dnsbl_session *, struct dnsbl_session *);

int
main(int argc, char *argv[])
{
	int ch;
	size_t i;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	char *msgid, *token, *ip;
	const char *errstr;
	int lookup;

	if (pledge("stdio dns", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "b:f:r:")) != -1) {
		switch (ch) {
		case 'b':
			blacklists = reallocarray(blacklists, nblacklists + 1,
			    sizeof(*blacklists));
			if (blacklists == NULL)
				err(1, NULL);
			if ((blacklists[nblacklists] = strdup(optarg)) == NULL)
				err(1, NULL);
			nblacklists++;
			break;
		default:
			usage();
		}
	}

	if (nblacklists == 0)
		errx(1, "No blacklist specified");

	smtp_register_filter_connect(dnsbl_connect);
	smtp_in_register_report_disconnect(dnsbl_disconnect);
	smtp_run();

	return 0;
}

void
dnsbl_connect(char *type, int version, struct timespec *tm, char *direction,
    char *phase, uint64_t reqid, uint64_t token, char *hostname,
    struct inx_addr *xaddr)
{
	struct dnsbl_session *session;
	struct timeval timeout = {1, 0};
	char query[255];
	u_char *addr;
	int i, try;

	if ((session = calloc(1, sizeof(*session))) == NULL)
		err(1, NULL);
	if ((session->query = calloc(nblacklists, sizeof(*(session->query))))
	    == NULL)
		err(1, NULL);
	session->reqid = reqid;
	session->token = token;
	RB_INSERT(dnsbl_sessions, &dnsbl_sessions, session);

	if (xaddr->af == AF_INET)
		addr = (u_char *)&(xaddr->addr);
	else
		addr = (u_char *)&(xaddr->addr6);
	for (i = 0; i < nblacklists; i++) {
		if (xaddr->af == AF_INET) {
			if (snprintf(query, sizeof(query), "%u.%u.%u.%u.%s",
			    addr[3], addr[2], addr[1], addr[0],
			    blacklists[i]) >= sizeof(query))
				errx(1, "Can't create query, domain too long");
		} else if (xaddr->af == AF_INET6) {
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
			    blacklists[i]) >= sizeof(query))
				errx(1, "Can't create query, domain too long");
		} else
			errx(1, "Invalid address family received");

		session->query[i].query = gethostbyname_async(query, NULL);
		session->query[i].event = event_asr_run(session->query[i].query,
		    dnsbl_resolve, &(session->query[i]));
		session->query[i].blacklist = i;
		session->query[i].session = session;
		evtimer_set(&(session->query[i].timeout), dnsbl_timeout,
		    &(session->query[i]));
		evtimer_add(&(session->query[i].timeout), &timeout);
	}
}

void
dnsbl_resolve(struct asr_result *result, void *arg)
{
	struct dnsbl_query *query = arg;
	struct dnsbl_session *session = query->session;
	int i, blacklist;

	query->resolved = 1;
	query->event = NULL;
	query->query = NULL;
	evtimer_del(&(query->timeout));
	if (result->ar_hostent != NULL) {
		smtp_filter_disconnect(session->reqid, session->token,
		    "Host listed at %s", blacklists[query->blacklist]);
		dnsbl_session_free(session);
		return;
	}
	if (result->ar_h_errno != HOST_NOT_FOUND) {
		smtp_filter_disconnect(session->reqid, session->token,
		    "DNS error on %s", blacklists[query->blacklist]);
		dnsbl_session_free(session);
		return;
	}

	for (i = 0; i < nblacklists; i++) {
		if (!session->query[i].resolved)
			return;
	}
	smtp_filter_proceed(session->reqid, session->token);
	dnsbl_session_free(session);
}

void
dnsbl_timeout(int fd, short event, void *arg)
{
	struct dnsbl_query *query = arg;
	struct dnsbl_session *session = query->session;

	smtp_filter_disconnect(session->reqid, session->token,
	    "DNS timeout on %s", blacklists[query->blacklist]);
	dnsbl_session_free(session);
}

void
dnsbl_disconnect(char *type, int version, struct timespec *tm, char *direction,
    char *phase, uint64_t reqid)
{
	struct dnsbl_session *session, search;

	search.reqid = reqid;
	if ((session = RB_FIND(dnsbl_sessions, &dnsbl_sessions, &search)) != NULL)
		dnsbl_session_free(session);
}

void
dnsbl_session_free(struct dnsbl_session *session)
{
	int i;

	RB_REMOVE(dnsbl_sessions, &dnsbl_sessions, session);
	for (i = 0; i < nblacklists; i++) {
		if (!session->query[i].resolved) {
			event_asr_abort(session->query[i].event);
			evtimer_del(&(session->query[i].timeout));
		}
	}
	free(session->query);
	free(session);
}

int
dnsbl_session_cmp(struct dnsbl_session *s1, struct dnsbl_session *s2)
{
	return (s1->reqid < s2->reqid ? -1 : s1->reqid > s2->reqid);
}

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-b blacklist]\n",
	    getprogname());
	exit(1);
}

RB_GENERATE(dnsbl_sessions, dnsbl_session, entry, dnsbl_session_cmp);
