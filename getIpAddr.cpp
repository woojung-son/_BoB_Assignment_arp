#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include "getIpAddr.h"
 
char* getIpAddr(char* dev)
{
    int fd;
    struct ifreq ifr;
	static char ip_buffer[20] = {0,};
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
     
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ -1);
    
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
     
    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	return ip_buffer;

}

