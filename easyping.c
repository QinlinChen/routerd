#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include "coredata.h"
#include "utils.h"
#include "error.h"
#include "sys.h"

int main(int argc, char *argv[])
{
    int sockfd;

    if (argc != 2)
        app_errq("Usage: %s <ip>", argv[0]);
    
	init_route_table_from_file(ROUTE_TABLE_FILE);
	init_arp_table_from_file(ARP_TABLE_FILE);
    init_dev_table_from_file(DEV_TABLE_FILE);

    if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1)
		unix_errq("socket error");

    struct in_addr dst;
    inet_aton(argv[1], &dst);
    send_icmp(sockfd, ICMP_ECHO, dst);

    return 0;
}