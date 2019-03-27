#include <sys/time.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smtp_proc.h"

#define NITEMS(x) (sizeof(x) / sizeof(*x))

typedef int (*smtp_cb)(char *, int, time_t, char *, char *, uint64_t, uint64_t,
    void *);

struct smtp_callback;

static int smtp_register(char *, char *, char *, smtp_cb);
static void smtp_connect(struct smtp_callback *, int, time_t, uint64_t,
    uint64_t, char *);
static void smtp_data(struct smtp_callback *, int, time_t, uint64_t, uint64_t,
    char *);
static void smtp_data_line(struct smtp_callback *, int, time_t, uint64_t,
    uint64_t, char *);
static void smtp_rset(struct smtp_callback *, int, time_t, uint64_t, uint64_t,
    char *);
static void smtp_quit(struct smtp_callback *, int, time_t, uint64_t, uint64_t,
    char *);
static void smtp_noop(struct smtp_callback *, int, time_t, uint64_t, uint64_t,
    char *);
static void smtp_help(struct smtp_callback *, int, time_t, uint64_t, uint64_t,
    char *);
static void smtp_wiz(struct smtp_callback *, int, time_t, uint64_t, uint64_t,
    char *);
static void smtp_commit(struct smtp_callback *, int, time_t, uint64_t, uint64_t,
    char *);
static void smtp_handle(struct smtp_callback *, int, time_t, uint64_t, uint64_t,
    void *);

struct smtp_callback {
	char *type;
	char *phase;
	char *direction;
	void (*smtp_parse)(struct smtp_callback *, int, time_t, uint64_t,
	    uint64_t, char *);
	smtp_cb cb;
} smtp_callbacks[] = {
	{"filter", "connect", "smtp-in", smtp_connect, NULL},
	{"filter", "data", "smtp-in", smtp_data, NULL},
	{"filter", "data-line", "smtp-in", smtp_data_line, NULL},
	{"filter", "rset", "smtp-in", smtp_rset, NULL},
	{"filter", "quit", "smtp-in", smtp_quit, NULL},
	{"filter", "noop", "smtp-in", smtp_noop, NULL},
	{"filter", "help", "smtp-in", smtp_help, NULL},
	{"filter", "wiz", "smtp-in", smtp_wiz, NULL},
	{"filter", "commit", "smtp-in", smtp_commit, NULL}
};

static int ready = 0;

int
smtp_register_filter_connect(enum filter_decision (*cb)(char *, int, time_t,
    char *, char *, uint64_t, uint64_t, struct smtp_filter_connect *))
{
	return smtp_register("filter", "connect", "smtp-in", (smtp_cb) cb);
}

void
smtp_run(void)
{
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	char *start, *end, *type, *direction, *phase, *params;
	int version;
	time_t tm;
	uint64_t reqid, token;
	int i;

	printf("register|ready\n");
	ready = 1;

	while ((linelen = getline(&line, &linesize, stdin)) != -1) {
		if (line[linelen - 1] != '\n')
			errx(1, "Invalid line received: missing newline");
		line[linelen - 1] = '\0';
		type = line;
		if ((start = strchr(type, '|')) == NULL)
			errx(1, "Invalid line received: missing version");
		start++[0] = '\0';
		if ((end = strchr(start, '|')) == NULL)
			errx(1, "Invalid line received: missing time");
		end++[0] = '\0';
		if (strcmp(start, "1") != 0)
			errx(1, "Unsupported protocol received: %s", start);
		version = 1;
		start = end;
		if ((direction = strchr(start, '|')) == NULL)
			errx(1, "Invalid line received: missing direction");
		direction++[0] = '\0';
		tm = (time_t) strtoull(start, &end, 10);
		if (start[0] == '\0' || end[0] != '\0')
			errx(1, "Invalid line received: invalid timestamp");
		if ((phase = strchr(direction, '|')) == NULL)
			errx(1, "Invalid line receieved: missing phase");
		phase++[0] = '\0';
		if ((start = strchr(phase, '|')) == NULL)
			errx(1, "Invalid line received: missing reqid");
		start++[0] = '\0';
		reqid = strtoull(start, &end, 16);
		if (start[0] == '|' || end[0] != '|')
			errx(1, "Invalid line received: invalid reqid");
		end++[0] = '\0';
		start = end;
		token = strtoull(start, &end, 16);
		if (start[0] == '|' || end[0] != '|')
			errx(1, "Invalid line received: invalid token");
		params = end + 1;

		for (i = 0; i < NITEMS(smtp_callbacks); i++) {
			if (strcmp(type, smtp_callbacks[i].type) == 0 &&
			    strcmp(phase, smtp_callbacks[i].phase) == 0 &&
			    strcmp(direction, smtp_callbacks[i].direction) == 0)
				break;
		}
		if (i == NITEMS(smtp_callbacks)) {
			errx(1, "Invalid line received: received unregistered "
			    "%s: %s", type, phase);
		}
		smtp_callbacks[i].smtp_parse(&(smtp_callbacks[i]), version, tm,
		    reqid, token, params);
	}
}

static void
smtp_connect(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
	struct smtp_filter_connect sfconnect;
	char *address;
	int ret;

	sfconnect.hostname = params;
	if ((address = strchr(params, '|')) == NULL)
		errx(1, "Invalid line received: missing address");
	address++[0] = '\0';

	sfconnect.af = AF_INET;
	if (strncasecmp(address, "ipv6:", 5) == 0) {
		sfconnect.af = AF_INET6;
		address += 5;
	}

	ret = inet_pton(sfconnect.af, address, sfconnect.af == AF_INET ?
	    (void *)&(sfconnect.addr) : (void *)&(sfconnect.addr6));
	if (ret == 0)
		errx(1, "Invalid line received: Couldn't parse address");
	if (ret == -1)
		err(1, "Couldn't convert address");

	smtp_handle(cb, version, tm, reqid, token, (void *)(&sfconnect));
}

static void 
smtp_data(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
}

static void 
smtp_data_line(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
}

static void 
smtp_rset(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
}

static void 
smtp_quit(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
}

static void 
smtp_noop(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
}

static void 
smtp_help(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
}

static void 
smtp_wiz(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
}

static void 
smtp_commit(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, char *params)
{
}

static void
smtp_handle(struct smtp_callback *cb, int version, time_t tm, uint64_t reqid,
    uint64_t token, void *params)
{
	int ret;

	switch (cb->cb(cb->type, version, tm, cb->direction, cb->phase, reqid,
	    token, params)) {
	case FILTER_PROCEED:
		printf("filter-result|%016"PRIx64"|%016"PRIx64"|proceed\n",
		    token, reqid);
		break;
	case FILTER_REJECT:
		printf("filter-result|%016"PRIx64"|%016"PRIx64"|reject|%s\n",
		    token, reqid, "451 Proper message later");
		break;
	case FILTER_DISCONNECT:
		printf("filter-result|%016"PRIx64"|%016"PRIx64"|disconnect|"
		    "%s\n", token, reqid, "421 Proper message later");
		break;
	case FILTER_REWRITE:
		errx(1, "Not sure what is intended here yet");
	}
}

static int
smtp_register(char *type, char *phase, char *direction, smtp_cb cb)
{
	int i;

	if (ready) {
		errx(1, "Can't register when proc is running");
	}
	for (i = 0; i < NITEMS(smtp_callbacks); i++) {
		if (strcmp(type, smtp_callbacks[i].type) == 0 &&
		    strcmp(phase, smtp_callbacks[i].phase) == 0 &&
		    strcmp(direction, smtp_callbacks[i].direction) == 0) {
			if (smtp_callbacks[i].cb != NULL) {
				errno = EALREADY;
				return -1;
			}
			smtp_callbacks[i].cb = cb;
			printf("register|%s|%s|%s\n", type, direction, phase);
			return 0;
		}
	}
	errno = EINVAL;
	return -1;
}


//filter|1|1553668146|smtp-in|connect|478cc771bf86f378|5161a9ce4540b4d1|<unknown>|100.64.7.2
