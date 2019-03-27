#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "smtp_proc.h"

static char **blacklists = NULL;
static size_t nblacklists = 0;
int retries = 0;
int reject_onfailure = 0;

void usage(void);
enum filter_decision dnsbl_connect(char *, int, time_t, char *, char *,
    uint64_t, uint64_t, struct smtp_filter_connect *);

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
		case 'f':
			reject_onfailure = 1;
		case 'r':
			if ((retries = strtonum(optarg, 0, 10, &errstr)) == 0 &&
			    errstr != NULL)
				errx(1, "retries %s", errstr);
			break;
		default:
			usage();
		}
	}

	if (nblacklists == 0)
		errx(1, "No blacklist specified");

	smtp_register_filter_connect(dnsbl_connect);
	smtp_run();

	return 0;
}

enum filter_decision
dnsbl_connect(char *type, int version, time_t tm, char *direction, char *phase,
    uint64_t reqid, uint64_t token, struct smtp_filter_connect *params)
{
	char query[255];
	char reply[1500];
	struct hostent *hent;
	u_char *addr;
	int i, try;

	addr = (u_char *)&(params->addr);
	for (i = 0; i < nblacklists; i++) {
		if (params->af == AF_INET) {
			if (snprintf(query, sizeof(query), "%u.%u.%u.%u.%s",
			    addr[3], addr[2], addr[1], addr[0],
			    blacklists[i]) >= sizeof(query))
				errx(1, "Can't create query, domain too long");
		} else if (params->af == AF_INET6) {
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

		for (try = -1; try < retries; try++) {
			if ((hent = gethostbyname(query)) == NULL) {
				if (h_errno == HOST_NOT_FOUND)
					break;
				if (h_errno != TRY_AGAIN) {
					if (!reject_onfailure)
						break;
					else
						smtp_filter_disconnect(reqid,
						    token,
						    "Blacklist check failed");
						return FILTER_DISCONNECT;
				}
			} else {
				smtp_filter_disconnect(reqid, token,
				    "Listed at %s", blacklists[i]);
				return FILTER_DISCONNECT;
			}
		}
	}
	return FILTER_PROCEED;
}

void
usage(void)
{
	fprintf(stderr, "usage: %s [-b blacklist]\n",
	    getprogname());
	exit(1);
}
