#ifndef _CORE_DATA_H
#define _CORE_DATA_H

#include <stdio.h>
#include <net/if.h>

/*
 * Route table and ARP table
 */
#define IP_STRLEN 16
#define MAC_STRLEN 18
#define MAX_ROUTE_SIZE 256
#define MAX_ARP_SIZE 256

struct route_item_t {
	char destination[IP_STRLEN];
	char gateway[IP_STRLEN];
	char netmask[IP_STRLEN];
	char interface[IF_NAMESIZE];
};

struct route_table_t {
	struct route_item_t items[MAX_ROUTE_SIZE];
	int size;
};

struct arp_item_t {
	char ip_addr[IP_STRLEN];
	char mac_addr[MAC_STRLEN];
};

struct arp_table_t {
	struct arp_item_t items[MAX_ARP_SIZE];
	int size;
};

extern struct route_table_t route_table;
extern struct arp_table_t arp_table;

void init_route_table_from_file(const char *filename);
void init_route_table_from_stream(FILE *fp);
void print_route_table();

void init_arp_table_from_file(const char *filename);
void init_arp_table_from_stream(FILE *fp);
void print_arp_table();

#endif