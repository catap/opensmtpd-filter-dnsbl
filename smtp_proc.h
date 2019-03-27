#include <netinet/in.h>

struct smtp_filter_connect {
	char *hostname;
	int af;
	union {
		struct in_addr addr;
		struct in6_addr addr6;
	};
};

enum filter_decision {
	FILTER_PROCEED = 0,
	FILTER_REJECT,
	FILTER_DISCONNECT,
	FILTER_REWRITE
};

int smtp_register_filter_connect(enum filter_decision (*cb)(char *, int, time_t,
    char *, char *, uint64_t, uint64_t, struct smtp_filter_connect *));
void smtp_run(void);
