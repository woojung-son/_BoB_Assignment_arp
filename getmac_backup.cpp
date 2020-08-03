
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
int main (int argc, char *argv[])
{
	printf("argv[1] : %s\n", argv[1]);
	printf("sizeof(argv[1]) : %d\n", sizeof(argv[1]));
	struct ifreq *iflist;
	struct sockaddr *sa;
	int fd;
	char *out;

	if(argc != 2)
	{
		printf("Usage: progname ifname (ex: progname eth0)\n");
		return -1;
	}

	iflist = (struct ifreq *)malloc (sizeof (struct ifreq));

	fd = socket (PF_INET, SOCK_STREAM, 0);

	strncpy (iflist->ifr_name, argv[1], strlen (argv[1]));

	if (ioctl (fd, SIOCGIFHWADDR, iflist) == -1)
	{
		perror ("ioctl failed");
		return -1;
	}

	sa = &(iflist->ifr_hwaddr);

	out = ether_ntoa ((struct ether_addr *) sa->sa_data);

	printf ("%s\n", out);

	return 0;
}
