#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <curses.h>
#include <assert.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <resolv.h>
#include <errno.h>

#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netdb.h>

#ifdef HAVE_NET_IF_PPP_H
#include <net/if_ppp.h>
#define PPP_ADDRESS_VAL       0xff	/* The address byte value */
#define PPP_CONTROL_VAL       0x03	/* The control byte value */
#endif

#define DNS_MSG_HDR_SZ 12
#define MAX_QNAME_SZ 512

#include "inX_addr.h"

typedef struct _rcode_str{
    ns_rcode    rcode;
    char        str[16];    
} rcode_str;

typedef struct _rrtype_str{
    ns_type    rrtype;
    char        str[16];    
} rrtype_str;

void usage(char *program);
void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) ;
int handle_ether(const u_char * pkt, int len);
int handle_ip(const u_char * pkt, int len, unsigned short etype);
int handle_ipv4(const struct ip *ip, int len);
int handle_ipv6(struct ip6_hdr *ipv6, int len);
int handle_udp(const struct udphdr *udp, int len, const inX_addr * src_addr, const inX_addr * dst_addr);
int handle_dns(const char *buf, int len, const inX_addr * src_addr, const inX_addr * dst_addr);
int rr_display(ns_msg * handle, ns_rr rr, ns_sect section );
int get_name( ns_msg *handle, ns_rr *rr, int offset, char *buff, int size_of_buff );
char *str_rcode(int rcode);

