#include <linux/if_tun.h>

int tun_alloc(char *dev, int flags);
int set_ip(const char* interface, const char* address, const char* mask);
