#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <common/tun/tun.h>

int tun_alloc(char *dev, int flags)
{

	struct ifreq ifr;
	int fd, err;
#ifdef __ANDROID__
	char *clonedev = "/dev/tun";
#else
	char *clonedev = "/dev/net/tun";
#endif

	if( (fd = open(clonedev, O_RDWR)) < 0 ) 
	{
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev)
	{
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	}

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 )
	{
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);
	return fd;
}

int set_ip(const char* interface, const char* address, const char* mask)
{
	int test_sock = 0;
	struct sockaddr_in* addr = NULL;
	struct ifreq ifr, ifr_mask, ifr_flag;

	memset(&ifr, 0, sizeof(struct ifreq));
	memset(&ifr_mask, 0, sizeof(struct ifreq));
	memset(&ifr_flag, 0, sizeof(struct ifreq));

	addr = (struct sockaddr_in *)&(ifr.ifr_addr);
	memset(addr, 0, sizeof( struct sockaddr_in) );
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(address);

	addr = (struct sockaddr_in *)&(ifr_mask.ifr_netmask);
	memset(addr, 0, sizeof( struct sockaddr_in) );
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(mask);

	ifr_flag.ifr_flags |= IFF_UP;
	strncpy(ifr.ifr_name, interface,IFNAMSIZ);
	strncpy(ifr_mask.ifr_name, interface,IFNAMSIZ);
	strncpy(ifr_flag.ifr_name, interface,IFNAMSIZ);

	test_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (test_sock == -1)
	{
		printf("Cannot obtain socket :%s\n", strerror(errno));
		return (-1);
	}

	if (ioctl(test_sock, SIOCSIFADDR, &ifr)			\
		|| ioctl(test_sock, SIOCSIFNETMASK, &ifr_mask)	\
		|| ioctl(test_sock, SIOCSIFFLAGS, &ifr_flag))
	{
		printf("Error configuring interface '%s' :%s\n", interface, strerror(errno));
		close(test_sock);
		return (-1);
	}
	else printf("IP address of '%s' set to '%s'\n", interface, address);
	close(test_sock);
	return(0);
}
