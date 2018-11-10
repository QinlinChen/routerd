#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include "utils.h"
#include "error.h"
#include "coredata.h"
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

uint16_t checksum(uint16_t *buf, int len)
{
    int nleft = len;
    uint32_t sum = 0;

    while (nleft > 1) {
        sum += *buf++;
        nleft -= 2;
    }

    /* Mop up an odd byte, if necessary. */
    if (nleft == 1) 
        sum += *(uint8_t *)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

#define ICMP_HDRSIZE    8
#define ICMP_DATASIZE   56
#define ICMP_SIZE       (ICMP_HDRSIZE + ICMP_DATASIZE)
#define IP_HDRSIZE      20

void send_icmp(int sockfd, int icmp_type, struct in_addr dst_ip)
{
    static int nsent = 0;
    static pid_t pid = 0;
    char sendbuf[BUFSIZE];
    struct sockaddr_ll addr_ll;

    if (pid == 0)
        pid = getpid();

    struct ip *ip = (struct ip *)sendbuf;
    struct icmp *icmp = (struct icmp *)(sendbuf + IP_HDRSIZE);

    /* construct icmp */
    icmp->icmp_type = icmp_type;
    icmp->icmp_code = 0;
    icmp->icmp_id = pid;
    icmp->icmp_seq = ++nsent;
    memset(icmp->icmp_data, 0xa5, ICMP_DATASIZE); /* Fill with pattern. */
    if (gettimeofday((struct timeval *)icmp->icmp_data, NULL) == -1)
        unix_errq("gettimeofday error");
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum((uint16_t *)icmp, ICMP_SIZE);

    /* construct ip */
    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(IP_HDRSIZE + ICMP_SIZE);
    ip->ip_id = htons((uint16_t)pid);
    ip->ip_off = htons((uint16_t)IP_DF);
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_dst = dst_ip;
	if (lookup_next_hop(dst_ip, &addr_ll, &ip->ip_src) != 0)
		app_errq("lookup_next_hop error");
    ip->ip_sum = 0;
    ip->ip_sum = checksum((uint16_t *)ip, IP_HDRSIZE + ICMP_SIZE);

    if (sendto(sockfd, sendbuf, IP_HDRSIZE + ICMP_SIZE, 0,
               (struct sockaddr *)&addr_ll, sizeof(addr_ll)) == -1)
        unix_errq("sendto error");
}