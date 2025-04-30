#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void MacToStr(uint8_t *mac, char *res){
    sprintf(res,"%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int GetMacAddress(const char *ifname, uint8_t *mac_addr){
	struct ifreq ifr;
       	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Fail to get interface Mac address - socket() failed - %m\n");
		return -1;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface Mac address - ioctl(SIOCSIFHWADDR) failed - %m\n");
		close(sockfd);
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
	close(sockfd);
	return 0;
}

