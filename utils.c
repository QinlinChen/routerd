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

void tv_sub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

void send_icmp(int sockfd, struct in_addr dst_ip)
{
    static int nsent = 0;
    static pid_t pid = 0;
    char sendbuf[BUFSIZE];
    struct sockaddr_ll next_hop;

    if (pid == 0)
        pid = getpid();

    struct ip *ip = (struct ip *)sendbuf;
    struct icmp *icmp = (struct icmp *)(sendbuf + IP_HLEN);

    /* construct icmp */
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = pid;
    icmp->icmp_seq = ++nsent;
    memset(icmp->icmp_data, 0xa5, ICMP_DLEN); /* Fill with pattern. */
    if (gettimeofday((struct timeval *)icmp->icmp_data, NULL) == -1)
        unix_errq("gettimeofday error");
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum((uint16_t *)icmp, ICMP_LEN);

    /* construct ip */
    ip->ip_hl = 5;
    ip->ip_v = 4;
    ip->ip_tos = 0;
    ip->ip_len = htons(IP_HLEN + ICMP_LEN);
    ip->ip_id = htons((uint16_t)pid);
    ip->ip_off = htons((uint16_t)IP_DF);
    ip->ip_ttl = 64;
    ip->ip_p = IPPROTO_ICMP;
    ip->ip_dst = dst_ip;
    if (lookup_next_hop(dst_ip, &next_hop, &ip->ip_src) != 0)
        app_errq("lookup_next_hop error");
    ip->ip_sum = 0;
    ip->ip_sum = checksum((uint16_t *)ip, IP_HLEN + ICMP_LEN);

    if (sendto(sockfd, sendbuf, IP_HLEN + ICMP_LEN, 0,
               (struct sockaddr *)&next_hop, sizeof(next_hop)) == -1)
        unix_errq("sendto error");
    
    printf("[send to]:\n");
    print_sockaddr_ll(&next_hop);
}

void reply_icmp(int sockfd, char *reqdata, size_t len)
{
    int iphlen, icmplen;
    struct ip *ip;
    struct icmp *icmp;
    struct sockaddr_ll next_hop;
    struct in_addr temp;

    ip = (struct ip *)reqdata;
    iphlen = ip->ip_hl << 2;
    icmp = (struct icmp *)(reqdata + iphlen);
    icmplen = len - iphlen;
    assert(icmp->icmp_type == ICMP_ECHO);

    /* modify icmp */
    icmp->icmp_type = ICMP_ECHOREPLY;
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = checksum((uint16_t *)icmp, icmplen);

    /* modify ip */
    temp = ip->ip_dst;
    ip->ip_dst = ip->ip_src;
    ip->ip_src = temp;
    if (lookup_next_hop(ip->ip_dst, &next_hop, NULL) != 0)
        app_errq("lookup_next_hop error");
    ip->ip_sum = 0;
    ip->ip_sum = checksum((uint16_t *)ip, len);

    if (sendto(sockfd, reqdata, len, 0,
               (struct sockaddr *)&next_hop, sizeof(next_hop)) == -1)
        unix_errq("sendto error");

    printf("[reply to]: \n");
    print_sockaddr_ll(&next_hop);
}

int is_to_us(struct sockaddr_ll *src_addr)
{
    return (src_addr->sll_pkttype == PACKET_HOST);
}

int is_to_forward(struct sockaddr_ll *src_addr)
{
    return 1;
}

void forward(int sockfd, char *fwddata, size_t len)
{
    struct ip *iphdr = (struct ip *)fwddata;
    struct sockaddr_ll next_hop;

    if (lookup_next_hop(iphdr->ip_dst, &next_hop, NULL) != 0)
        app_errq("fail to forward");

    if (sendto(sockfd, fwddata, len, 0,
               (struct sockaddr *)&next_hop, sizeof(next_hop) == -1))
        unix_errq("sendto error");

    printf("[forward to]:\n");
    print_sockaddr_ll(&next_hop);
}