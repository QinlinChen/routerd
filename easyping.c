#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include "coredata.h"
#include "utils.h"
#include "error.h"
#include "sys.h"

void listenloop(int sockfd);
void process(int sockfd, char *reqdata, size_t len);
void process_icmp(int sockfd, char *reqdata, size_t len);

int main(int argc, char *argv[])
{
    int sockfd;
    struct in_addr dst;

    if (argc != 2)
        app_errq("Usage: %s <ip>", argv[0]);
    
    init_route_table_from_file(ROUTE_TABLE_FILE);
    init_arp_table_from_file(ARP_TABLE_FILE);
    init_dev_table_from_file(DEV_TABLE_FILE);

    if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1)
        unix_errq("socket error");

    inet_aton(argv[1], &dst);
    send_icmp(sockfd, dst);

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
        
        if (is_to_us(buf, nrecv))
            process(sockfd, buf, nrecv);
    }
}

void process(int sockfd, char *reqdata, size_t len)
{
    struct ip *iphdr = (struct ip *)reqdata;

    switch (iphdr->ip_p) {
        case IPPROTO_ICMP: 
            process_icmp(sockfd, reqdata, len);
            break;
        default: /* Only handle ICMP */
            break;
    }
}

void process_icmp(int sockfd, char *reqdata, size_t len)
{
    int iphlen, iplen, icmplen;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval tvrecv, *tvsend;
    double rtt;

    ip = (struct ip *)reqdata;
    iphlen = ip->ip_hl << 2;
    iplen = ntohs(ip->ip_len);
    assert(ip->ip_p == IPPROTO_ICMP);
    assert(iplen <= len);

    icmp = (struct icmp *)(reqdata + iphlen);
    icmplen = len - iphlen;
    if (icmplen < ICMP_HLEN)
        return; /* Discard malformed packet. */	

    if (icmp->icmp_type == ICMP_ECHOREPLY) {
        if (icmp->icmp_id != getpid())
            return; /* Not a response to our ECHO_REQUEST. */
        if (icmplen < ICMP_HLEN + sizeof(struct timeval))
            return; /* Not enough data to use. */

        /* Calculate rtt. */
        if (gettimeofday(&tvrecv, NULL) == -1)
            unix_errq("gettimeofday error");
        tvsend = (struct timeval *)icmp->icmp_data;
        tv_sub(&tvrecv, tvsend);
        rtt = tvrecv.tv_sec * 1000.0 + tvrecv.tv_usec / 1000.0;

        printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
               icmplen, inet_ntoa(ip->ip_src),
               icmp->icmp_seq, ip->ip_ttl, rtt);
        exit(0);
    }
}