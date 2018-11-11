#ifndef _UTILS_H
#define _UTILS_H

#include <stdint.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <netinet/in.h>

const char *pkttype_to_str(unsigned char pkttype);
const char *ipproto_to_str(int protocal);
char *mac_bintostr(unsigned char *macbin, char *macstr);
unsigned char *mac_strtobin(char *macstr, unsigned char *macbin);

void print_llframe(struct sockaddr_ll *src_addr, char *data, size_t len);
void print_sockaddr_ll(struct sockaddr_ll *addr);
void print_ipdatagram(char *data, size_t len);

uint16_t checksum(uint16_t *buf, int len);
void tv_sub(struct timeval *out, struct timeval *in);

#define ICMP_HLEN   8
#define ICMP_DLEN	56
#define ICMP_LEN    (ICMP_HLEN + ICMP_DLEN)
#define IP_HLEN     20

void send_icmp(int sockfd, struct in_addr dst_ip);
void reply_icmp(int sockfd, char *reqdata, size_t len);

int is_to_us(char *ipdatagram, size_t len);
int is_to_forward(struct sockaddr_ll *src_addr);
void forward(int sockfd, char *fwddata, size_t len);

#endif