#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include "utils.h"
#include "common.h"
#include "sys.h"

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

void print_sockaddr_ll(struct sockaddr_ll *addr)
{
	char ifname[IF_NAMESIZE];
	char macstr[MAC_STRLEN];

	assert(if_indextoname(addr->sll_ifindex, ifname));
	assert(mac_bintostr(addr->sll_addr, macstr));
	printf("ifname: %s, pkttype: %s\n",
		   ifname, pkttype_to_str(addr->sll_pkttype));
	printf("macaddr: %s\n", macstr);
}

void print_ipdatagram(char *data, size_t len)
{
	struct ip *iphdr = (struct ip *)data;
	printf("length: %u(%d), protocal: %s\n", 
		   (unsigned int)ntohs(iphdr->ip_len),
		   (int)len, ipproto_to_str(iphdr->ip_p));
	printf("src: %s, ", inet_ntoa(iphdr->ip_src));
	printf("dst: %s\n", inet_ntoa(iphdr->ip_dst));
}

void print_llframe(struct sockaddr_ll *src_addr, char *data, size_t len)
{
	static int ctr = 0;

	printf("[%d] ", ctr++);
	print_sockaddr_ll(src_addr);
	print_ipdatagram(data, len);
}
