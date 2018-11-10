#include "coredata.h"
#include "error.h"

struct route_table_t route_table;
struct arp_table_t arp_table;

void init_route_table_from_file(const char *filename)
{
	FILE *fp;

	if ((fp = fopen(filename, "r")) == NULL)
		unix_errq("fopen error");

	init_route_table_from_stream(fp);

	if (fclose(fp) != 0)
		unix_errq("fclose error");
}

void init_route_table_from_stream(FILE *fp)
{
	int ret;
	struct route_item_t *itemp;

	route_table.size = 0;
	itemp = route_table.items;
	while ((ret = fscanf(fp, "%s %s %s %s",
					     itemp->destination, itemp->gateway,
				         itemp->netmask, itemp->interface)) == 4) {
		itemp++;
		route_table.size++;
		if (route_table.size == MAX_ROUTE_SIZE)
			app_errq("exceed maximum route table size.");
	}
	if (ret != EOF)
		app_errq("data format error");
	else if (ferror(fp))
		unix_errq("fscanf error");
}

void print_route_table()
{
	struct route_item_t *itemp, *end;
	
	itemp = route_table.items;
	end = route_table.items + route_table.size;
	printf("%-19s%-19s%-19s%-19s\n",
		   "destination", "gateway",
		   "netmask", "interface");
	while (itemp != end) {
		printf("%-19s%-19s%-19s%-19s\n",
			   itemp->destination, itemp->gateway,
			   itemp->netmask, itemp->interface);
		itemp++;
	}
}

void init_arp_table_from_file(const char *filename)
{
	FILE *fp;

	if ((fp = fopen(filename, "r")) == NULL)
		unix_errq("fopen error");

	init_arp_table_from_stream(fp);

	if (fclose(fp) != 0)
		unix_errq("fclose error");
}

void init_arp_table_from_stream(FILE *fp)
{
	int ret;
	struct arp_item_t *itemp;

	arp_table.size = 0;
	itemp = arp_table.items;
	while ((ret = fscanf(fp, "%s %s",
					     itemp->ip_addr, itemp->mac_addr)) == 2) {
		itemp++;
		arp_table.size++;
		if (arp_table.size == MAX_ARP_SIZE)
			app_errq("exceed maximum arp table size");
	}
	if (ret != EOF)
		app_errq("data format error");
	else if (ferror(fp))
		unix_errq("fscanf error");
}

void print_arp_table()
{
	struct arp_item_t *itemp, *end;
	
	itemp = arp_table.items;
	end = arp_table.items + route_table.size;
	printf("%-19s%-21s\n", "ip_addr", "mac_addr");
	while (itemp != end) {
		printf("%-19s%-21s\n", itemp->ip_addr, itemp->mac_addr);
		itemp++;
	}
}