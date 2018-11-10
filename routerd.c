#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include "coredata.h"
#include "utils.h"
#include "error.h"
#include "sys.h"

void listenloop(int sockfd);
int is_to_us(struct sockaddr_ll *src_addr);
int is_to_forward(struct sockaddr_ll *src_addr);
void response(int sockfd, char *reqdata, size_t len);
void forward(int sockfd, char *fwddata, size_t len);

int main()
{
	int sockfd;

	init_route_table_from_file("route.txt");
	init_arp_table_from_file("arp.txt");
	print_route_table();
	print_arp_table();

	if ((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1)
		unix_errq("socket error");
	
	struct sockaddr_ll ll;
	struct in_addr addr;
	inet_aton("192.168.2.100", &addr);
	lookup_next_hop(addr, &ll);
	print_sockaddr_ll(&ll);
	// listenloop(sockfd);

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
			response(sockfd, buf, nrecv);
		else if (is_to_forward(&addr))
			forward(sockfd, buf, nrecv);
		/* else discard packet. */
	}
}

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

int is_to_us(struct sockaddr_ll *src_addr)
{
	return src_addr->sll_pkttype == PACKET_HOST;
}

int is_to_forward(struct sockaddr_ll *src_addr)
{
	return 1;
}

void response(int sockfd, char *reqdata, size_t len)
{
	/* TODO */
}

void forward(int sockfd, char *fwddata, size_t len)
{

}