#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include "coredata.h"
#include "utils.h"
#include "error.h"
#include "sys.h"

struct route_table_t route_table;
struct arp_table_t arp_table;
struct dev_table_t dev_table;

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
    
    end = route_table.items + route_table.size;
    printf("%-19s%-19s%-19s%s\n",
           "destination", "gateway",
           "netmask", "interface");
    for (itemp = route_table.items; itemp != end; ++itemp) {
        printf("%-19s%-19s%-19s%s\n",
               itemp->destination, itemp->gateway,
               itemp->netmask, itemp->interface);
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

    end = arp_table.items + arp_table.size;
    printf("%-19s%s\n", "ip_addr", "mac_addr");
    for (itemp = arp_table.items; itemp != end; ++itemp) {
        printf("%-19s%s\n", itemp->ip_addr, itemp->mac_addr);
    }
}

void init_dev_table_from_file(const char *filename)
{
    FILE *fp;

    if ((fp = fopen(filename, "r")) == NULL)
        unix_errq("fopen error");

    init_dev_table_from_stream(fp);

    if (fclose(fp) != 0)
        unix_errq("fclose error");
}

void init_dev_table_from_stream(FILE *fp)
{
    int ret;
    struct dev_item_t *itemp;

    dev_table.size = 0;
    itemp = dev_table.items;
    while ((ret = fscanf(fp, "%s %s",
                         itemp->interface, itemp->inetaddr)) == 2) {
        itemp++;
        dev_table.size++;
        if (dev_table.size == MAX_DEV_SIZE)
            app_errq("exceed maximum arp table size");
    }
    if (ret != EOF)
        app_errq("data format error");
    else if (ferror(fp))
        unix_errq("fscanf error");
}

void print_dev_table()
{
    struct dev_item_t *itemp, *end;

    end = dev_table.items + dev_table.size;
    printf("%-19s%s\n", "interface", "inetaddr");
    for (itemp = dev_table.items; itemp != end; ++itemp) {
        printf("%-19s%s\n", itemp->interface, itemp->inetaddr);
    }
}

int is_bound_to_dev(const char *ip)
{
    struct dev_item_t *itemp, *end;

    end = dev_table.items + dev_table.size;
    for (itemp = dev_table.items; itemp != end; ++itemp)
        if (strcmp(itemp->inetaddr, ip) == 0)
            return 1;
    return 0;
}

struct dev_item_t *lookup_dev_table(const char *interface)
{
    struct dev_item_t *itemp, *end;

    end = dev_table.items + dev_table.size;
    for (itemp = dev_table.items; itemp != end; ++itemp)
        if (strcmp(itemp->interface, interface) == 0)
            return itemp;
    return NULL;
}

struct route_item_t *lookup_route_table(struct in_addr dst_addr)
{
    struct route_item_t *routep, *route_end;
    struct route_item_t *default_item = NULL;
    struct in_addr netmask, destination;

    route_end = route_table.items + route_table.size;
    for (routep = route_table.items; routep != route_end; ++routep) {
        if (strcmp(routep->destination, "default") == 0) {
            default_item = routep;
        }
        else {
            assert(inet_aton(routep->netmask, &netmask));
            assert(inet_aton(routep->destination, &destination));
            if ((netmask.s_addr & dst_addr.s_addr) == destination.s_addr)
                return routep;
        }
    }
    if (default_item)
        return default_item;
    return NULL;
}

struct arp_item_t *lookup_arp_table(const char *ip_addr)
{
    struct arp_item_t *arpp, *arp_end;

    arp_end = arp_table.items + arp_table.size;
    for (arpp = arp_table.items; arpp != arp_end; ++arpp)
        if (strcmp(ip_addr, arpp->ip_addr) == 0)
            return arpp;
    return NULL;
}

int lookup_next_hop(struct in_addr dst_addr, struct sockaddr_ll *next_hop,
                    struct in_addr *if_addr)
{
    struct route_item_t *routep;
    struct arp_item_t *arpp;
    struct dev_item_t *devp;
    const char *next_hop_ip;
    unsigned char macbin[ETH_ALEN];

    if ((routep = lookup_route_table(dst_addr)) == NULL)
        return -1;

    /* Get next hop's ip. */
    next_hop_ip = (strcmp(routep->gateway, "*") == 0)
                      ? inet_ntoa(dst_addr)
                      : routep->gateway;
    if ((arpp = lookup_arp_table(next_hop_ip)) == NULL)
        return -1;

    /* Fill 'struct sockaddr_ll next_hop'. */
    assert(next_hop != NULL);
    next_hop->sll_family = AF_PACKET;
    next_hop->sll_protocol = htons(ETH_P_IP);
    next_hop->sll_halen = ETH_ALEN;
    if ((next_hop->sll_ifindex = if_nametoindex(routep->interface)) == 0)
        unix_errq("if_nametoindex error");
    mac_strtobin(arpp->mac_addr, macbin);
    memcpy(next_hop->sll_addr, macbin, ETH_ALEN);

    /* Fill if_addr */
    devp = lookup_dev_table(routep->interface);
    if (if_addr && (inet_aton(devp->inetaddr, if_addr) != 1))
        unix_errq("inet_aton error");
    return 0;
}