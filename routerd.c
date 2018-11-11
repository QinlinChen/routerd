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

    init_route_table_from_file(ROUTE_TABLE_FILE);
    init_arp_table_from_file(ARP_TABLE_FILE);
    init_dev_table_from_file(DEV_TABLE_FILE);
    print_route_table();
    print_arp_table();
    print_dev_table();

    if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1)
        unix_errq("socket error");
    
    listenloop(sockfd);

    return 0;
}

void listenloop(int sockfd)
{
    static int ctr = 0;
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    ssize_t nrecv;
    char buf[BUFSIZE];

    while (1) {
        if ((nrecv = recvfrom(sockfd, buf, BUFSIZE, 0,
                              (struct sockaddr *)&addr, &addr_len)) == -1)
            unix_errq("recv error");
        
        if (is_from_dev_in_dev_table(&addr)) {
            printf("\33[1;34m[recv %d]:\33[0m\n", ctr++);
            print_llframe(&addr, buf, nrecv);

            if (is_to_us(buf, nrecv))
                process(sockfd, buf, nrecv);
            else if (is_to_forward(&addr))
                forward(sockfd, buf, nrecv);
            /* else discard packet. */
        }
    }
}

void process(int sockfd, char *reqdata, size_t len)
{
    struct ip *iphdr = (struct ip *)reqdata;

    switch (iphdr->ip_p) {
        case IPPROTO_ICMP: 
            process_icmp(sockfd, reqdata, len);
            break;
        default: /* To handle more protocals */
            break;
    }
}

void process_icmp(int sockfd, char *reqdata, size_t len)
{
    int iphlen, iplen, icmplen;
    struct ip *ip;
    struct icmp *icmp;

    ip = (struct ip *)reqdata;
    iphlen = ip->ip_hl << 2;
    iplen = ntohs(ip->ip_len);
    assert(ip->ip_p == IPPROTO_ICMP);
    assert(iplen <= len);

    icmp = (struct icmp *)(reqdata + iphlen);
    icmplen = len - iphlen;
    if (icmplen < ICMP_HLEN)
        return; /* Discard malformed packet. */	

    if (icmp->icmp_type == ICMP_ECHO)
        reply_icmp(sockfd, reqdata, len);
}