#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include "error.h"
#include "coredata.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define BUFSIZE 8096

ssize_t send_ll_ip(int sockfd, int if_index, char dest_mac_addr[ETH_ALEN],
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

void listenloop(int sockfd);
int is_to_us(struct sockaddr_ll *src_addr);
int is_to_forward(struct sockaddr_ll *src_addr);
void response(int sockfd, char *reqdata, size_t len);
void forward(int sockfd, char *fwddata, size_t len);

void print_llframe(struct sockaddr_ll *src_addr, char *frame, size_t len);
const char *pkttype_to_str(unsigned char pkttype);
char *mac_bintostr(unsigned char *macbin, char *macstr);
unsigned char *mac_strtobin(char *macstr, unsigned char *macbin);
const char *ipproto_to_str(int protocal);


int main()
{
	int sockfd;

	init_route_table_from_file("route.txt");
	init_arp_table_from_file("arp.txt");
	print_route_table();
	print_arp_table();

	if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1)
		unix_errq("socket error");
		
	listenloop(sockfd);

	return 0;
}

void listenloop(int sockfd)
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	ssize_t nrecv;
	char buf[BUFSIZE];

	while (1) {
		if ((nrecv = recvfrom(sockfd, buf, BUFSIZE, 0,
							  (struct sockaddr *)&addr, &addr_len)) == -1)
			unix_errq("recv error");
		
		print_llframe(&addr, buf, nrecv);

	}
}

void print_llframe(struct sockaddr_ll *src_addr, char *frame, size_t len)
{
	static int ctr = 0;
	char ifname[IF_NAMESIZE];
	char macstr[MAC_STRLEN];

	assert(if_indextoname(src_addr->sll_ifindex, ifname));
	assert(mac_bintostr(src_addr->sll_addr, macstr));

	printf("[%d] ifname: %s, pkttype: %s\n", ctr++,
		   ifname, pkttype_to_str(src_addr->sll_pkttype));
	printf("macaddr: %s\n", macstr);

	struct ip *iphdr = (struct ip *)frame;
	printf("length: %u(%d), protocal: %s\n", 
		   (unsigned int)ntohs(iphdr->ip_len),
		   (int)len, ipproto_to_str(iphdr->ip_p));
	printf("src: %s, ", inet_ntoa(iphdr->ip_src));
	printf("dst: %s\n", inet_ntoa(iphdr->ip_dst));
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
		default: return "unknown";
	}
	return NULL;
}

char *mac_bintostr(unsigned char *macbin, char *macstr)
{
	snprintf(macstr, MAC_STRLEN, "%02x:%02x:%02x:%02x:%02x:%02x",
		     macbin[0], macbin[1], macbin[2], macbin[3],
			 macbin[4], macbin[5]);
	return macstr;
}

unsigned char *mac_strtobin(char *macstr, unsigned char *macbin)
{
	unsigned int buf[6];
	sscanf(macstr, "%x:%x:%x:%x:%x:%x", &buf[0], &buf[1],
		   &buf[2], &buf[3], &buf[4], &buf[5]);
	for (int i = 0; i < 6; ++i)
		macbin[i] = (unsigned char)buf[i];
	return macbin;
}

const char *ipproto_to_str(int protocal)
{
	switch (protocal) {
		case IPPROTO_ICMP: return "ICMP";
		case IPPROTO_TCP: return "TCP";
		case IPPROTO_UDP: return "UDP";
		case IPPROTO_SCTP: return "SCTP";
		default: return "Others";
	}
	return NULL;
}