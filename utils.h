#ifndef _UTILS_H
#define _UTILS_H

#include <sys/types.h>
#include <linux/if_packet.h>

const char *pkttype_to_str(unsigned char pkttype);
const char *ipproto_to_str(int protocal);
char *mac_bintostr(unsigned char *macbin, char *macstr);
unsigned char *mac_strtobin(char *macstr, unsigned char *macbin);

void print_llframe(struct sockaddr_ll *src_addr, char *data, size_t len);
void print_sockaddr_ll(struct sockaddr_ll *addr);
void print_ipdatagram(char *data, size_t len);

#endif