#include <sys/time.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smtp_proc.h"

#define NITEMS(x) (sizeof(x) / sizeof(*x))

struct smtp_callback;
struct smtp_request;

static int smtp_register(char *, char *, char *, void *);
static void smtp_newline(int, short, void *);
static void smtp_connect(struct smtp_callback *, int, struct timespec *,
    uint64_t, uint64_t, char *);

struct smtp_callback {
	char *type;
	char *phase;
	char *direction;
	void (*smtp_parse)(struct smtp_callback *, int, struct timespec *,
	    uint64_t, uint64_t, char *);
	void *cb;
} smtp_callbacks[] = {
        {"filter", "connect", "smtp-in", smtp_connect, NULL}
};

static int ready = 0;

int
smtp_register_filter_connect(void (*cb)(char *, int, struct timespec *, char *,
    char *, uint64_t, uint64_t, char *, struct inx_addr *))
{
	return smtp_register("filter", "connect", "smtp-in", (void *)cb);
}

void
smtp_run(void)
{
	struct event stdinev;

	printf("register|ready\n");
	fflush(stdout);
	ready = 1;

	event_init();
	event_set(&stdinev, STDIN_FILENO, EV_READ | EV_PERSIST, smtp_newline,
	    &stdinev);
	event_add(&stdinev, NULL);

	if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) == -1)
		err(1, "fcntl");
	event_dispatch();
}

static void
smtp_newline(int fd, short event, void *arg)
{
	struct event *stdinev = (struct event *)arg;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	char *start, *end, *type, *direction, *phase, *params;
	int version;
	struct timespec tm;
	uint64_t reqid, token;
	int i;

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
		tm.tv_sec = (time_t) strtoull(start, &end, 10);
		tm.tv_nsec = 0;
		if (start[0] == '\0' || (end[0] != '\0' && end[0] != '.'))
			errx(1, "Invalid line received: invalid timestamp");
		if (end[0] == '.') {
			start = end + 1;
			tm.tv_nsec = strtol(start, &end, 10);
			if (start[0] == '\0' || end[0] != '\0')
				errx(1, "Invalid line received: invalid "
				    "timestamp");
			for (i = 9 - (end - start); i > 0; i--)
				tm.tv_nsec *= 10;
		}
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
		smtp_callbacks[i].smtp_parse(&(smtp_callbacks[i]), version, &tm,
		    reqid, token, params);
	}
	if (feof(stdin) || (ferror(stdin) && errno != EAGAIN))
		event_del(stdinev);
}

static void
smtp_connect(struct smtp_callback *cb, int version, struct timespec *tm,
    uint64_t reqid, uint64_t token, char *params)
{
	struct inx_addr addrx;
	char *hostname;
	char *address;
	int ret;
	void (*f)(char *, int, struct timespec *,char *, char *, uint64_t,
	    uint64_t, char *, struct inx_addr *);

	hostname = params;
	if ((address = strchr(params, '|')) == NULL)
		errx(1, "Invalid line received: missing address");
	address++[0] = '\0';

	addrx.af = AF_INET;
	if (strncasecmp(address, "ipv6:", 5) == 0) {
		addrx.af = AF_INET6;
		address += 5;
	}

	ret = inet_pton(addrx.af, address, addrx.af == AF_INET ?
	    (void *)&(addrx.addr) : (void *)&(addrx.addr6));
	if (ret == 0)
		errx(1, "Invalid line received: Couldn't parse address");
	if (ret == -1)
		err(1, "Couldn't convert address");

	f = cb->cb;
	f(cb->type, version, tm, cb->direction, cb->phase, reqid, token,
	    hostname, &addrx);
}

void
smtp_filter_proceed(uint64_t reqid, uint64_t token)
{
	printf("filter-result|%016"PRIx64"|%016"PRIx64"|proceed\n", token,
	    reqid);
	fflush(stdout);
}

void
smtp_filter_reject(uint64_t reqid, uint64_t token, int code,
    const char *reason, ...)
{
	va_list ap;

	if (code < 200 || code > 599)
		errx(1, "Invalid reject code");

	printf("filter-result|%016"PRIx64"|%016"PRIx64"|reject|%d ", token,
	    reqid, code);
	va_start(ap, reason);
	vprintf(reason, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

void
smtp_filter_disconnect(uint64_t reqid, uint64_t token, const char *reason, ...)
{
	va_list ap;

	printf("filter-result|%016"PRIx64"|%016"PRIx64"|disconnect|421 ",
	    token, reqid);
	va_start(ap, reason);
	vprintf(reason, ap);
	va_end(ap);
	putchar('\n');
	fflush(stdout);
}

static int
smtp_register(char *type, char *phase, char *direction, void *cb)
{
	int i;

	if (ready)
		errx(1, "Can't register when proc is running");

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
