#include <netinet/in.h>

#include <netinet/in.h>

struct inx_addr {
	int af;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
};

int smtp_register_filter_connect(void (*cb)(char *, int, struct timespec *,
    char *, char *, uint64_t, uint64_t, char *, struct inx_addr *));
void smtp_filter_proceed(uint64_t, uint64_t);
void smtp_filter_reject(uint64_t, uint64_t, int, const char *, ...)
	__attribute__((__format__ (printf, 4, 5)));
void smtp_filter_disconnect(uint64_t, uint64_t, const char *, ...)
	__attribute__((__format__ (printf, 3, 4)));
void smtp_run(void);
