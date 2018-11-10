#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define BUFSIZE 1024

ssize_t sendto_ll_ip(int sockfd, int if_index, char dest_mac_addr[ETH_ALEN],
					 char *buf, size_t len)
{
	struct sockaddr_ll dest_addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_halen = ETH_ALEN,
		.sll_ifindex = if_index,
	};
	memcpy(dest_addr.sll_addr, dest_mac_addr, ETH_ALEN);
	return sendto(sockfd, buf, len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
}

ssize_t recvfrom_ll_ip(int sockfd, unsigned char *pkttype,
			           char *buf, size_t len)
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	ssize_t ret;

	ret = recvfrom(sockfd, buf, len, 0, (struct sockaddr *)&addr, &addr_len);
	if (pkttype)
		*pkttype = addr.sll_pkttype;
	return ret;
}

const char *pkttype_to_str(unsigned char pkttype)
{
	switch (pkttype) {
		case PACKET_BROADCAST: return "To all";
		case PACKET_HOST: return "To us";
		case PACKET_MULTICAST: return "To group";
		case PACKET_OTHERHOST: return "To someone else";
		case PACKET_OUTGOING: return "Outgoing of any type";
		case PACKET_LOOPBACK: return "MC/BRD frame looped back";
		default: return NULL;
	}
	return NULL;
}

int main()
{
    int sockfd, len, ctr = 0;
	unsigned char pkttype;
	char buf[BUFSIZE];

	if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL))) == -1) {
		perror("socket error");
		exit(1);
	}
	while ((len = recvfrom_ll_ip(sockfd, &pkttype, buf, BUFSIZE)) != -1) {
		printf("%d: length: %d, pkttype: %s\n", ctr++, len, pkttype_to_str(pkttype));
	}
	perror("recvfrom error");
}