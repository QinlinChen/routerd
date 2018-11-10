#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include "coredata.h"
#include "utils.h"
#include "error.h"
#include "sys.h"

void listenloop(int sockfd);
int is_to_us(struct sockaddr_ll *src_addr);
int is_to_forward(struct sockaddr_ll *src_addr);
void process(int sockfd, char *reqdata, size_t len);
void process_icmp(int sockfd, char *reqdata, size_t len);
void forward(int sockfd, char *fwddata, size_t len);

int main(int argc, char *argv[])
{
	int sockfd;

	init_route_table_from_file(ROUTE_TABLE_FILE);
	init_arp_table_from_file(ARP_TABLE_FILE);
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

		if (is_to_us(&addr))
			process(sockfd, buf, nrecv);
		else if (is_to_forward(&addr))
			forward(sockfd, buf, nrecv);
		/* else discard packet. */
	}
}

int is_to_us(struct sockaddr_ll *src_addr)
{
	return (src_addr->sll_pkttype == PACKET_HOST);
}

int is_to_forward(struct sockaddr_ll *src_addr)
{
	return 1;
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
	printf("process icmp\n");
	/* TODO */
}

void forward(int sockfd, char *fwddata, size_t len)
{
	struct ip *iphdr = (struct ip *)fwddata;
	struct sockaddr_ll next_hop;

	if (lookup_next_hop(iphdr->ip_dst, &next_hop, NULL) == 0) {
		sendto(sockfd, fwddata, len, 0,
				(struct sockaddr *)&next_hop, sizeof(next_hop));
		printf("forwarded to:\n");
		print_sockaddr_ll(&next_hop);
	}
	printf("fail to forward\n");
}