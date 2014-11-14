#include "dns-parser.h"
#include "inX_addr.h"
#include "list.h"
#include "trie.h"
#include "mystring.h"


//#define TRUE_FALSE(a) (a == 1) ? 'T':'F'

extern int h_errno;
extern int errno;

char unknown[] = "UNKNOWN";

pcap_t *pcap = NULL;
char * input_file=NULL;
char * output_file=NULL;
char * log_file=NULL;
char * list_file=NULL;

FILE *outh = NULL; //=stdout;
FILE *logh = NULL; //=stderr; 
FILE *listh = NULL; //=stderr; 
long timestamp=0;
in_addr_t ns_ip=0;
RRdata *pdata;
trieNode_t *tree;
char *qname;
char authoritative=0;
char recursive_desired = 0;  //ns_msg_getflag(handle, ns_f_rd);


rrtype_str rrtype2str[] ={
	{ns_t_invalid, "INVLD" }, // 0,	/*%< Cookie. */
	{ns_t_a, "A" }, // 1,		/*%< Host address. */
	{ns_t_ns, "NS" }, // 2,		/*%< Authoritative server. */
	{ns_t_md, "MD" }, // 3,		/*%< Mail destination. */
	{ns_t_mf, "MF" }, // 4,		/*%< Mail forwarder. */
	{ns_t_cname, "CNAME" }, // 5,		/*%< Canonical name. */
	{ns_t_soa, "SOA" }, // 6,		/*%< Start of authority zone. */
	{ns_t_mb, "MB" }, // 7,		/*%< Mailbox domain name. */
	{ns_t_mg, "MG" }, // 8,		/*%< Mail group member. */
	{ns_t_mr, "MR" }, // 9,		/*%< Mail rename name. */
	{ns_t_null, "NULL" }, // 10,		/*%< Null resource record. */
	{ns_t_wks, "WKS" }, // 11,		/*%< Well known service. */
	{ns_t_ptr, "PTR" }, // 12,		/*%< Domain name pointer. */
	{ns_t_hinfo, "HINFO" }, // 13,	/*%< Host information. */
	{ns_t_minfo, "MINF" }, // 14,	/*%< Mailbox information. */
	{ns_t_mx, "MX" }, // 15,		/*%< Mail routing information. */
	{ns_t_txt, "TXT" }, // 16,		/*%< Text strings. */
	{ns_t_rp, "RP" }, // 17,		/*%< Responsible person. */
	{ns_t_afsdb, "AFSDB" }, // 18,	/*%< AFS cell database. */
	{ns_t_x25, "X25" }, // 19,		/*%< X_25 calling address. */
	{ns_t_isdn, "ISDN" }, // 20,		/*%< ISDN calling address. */
	{ns_t_rt, "RT" }, // 21,		/*%< Router. */
	{ns_t_nsap, "NSAP" }, // 22,		/*%< NSAP address. */
	{ns_t_nsap_ptr, "NSAPPTR" }, // 23,	/*%< Reverse NSAP lookup (deprecated). */
	{ns_t_sig, "SIG" }, // 24,		/*%< Security signature. */
	{ns_t_key, "KEY" }, // 25,		/*%< Security key. */
	{ns_t_px, "PX" }, // 26,		/*%< X.400 mail mapping. */
	{ns_t_gpos, "GPOS" }, // 27,		/*%< Geographical position (withdrawn). */
	{ns_t_aaaa, "AAAA" }, // 28,		/*%< Ip6 Address. */
	{ns_t_loc, "LOC" }, // 29,		/*%< Location Information. */
	{ns_t_nxt, "NXT" }, // 30,		/*%< Next domain (security). */
	{ns_t_eid, "EID" }, // 31,		/*%< Endpoint identifier. */
	{ns_t_nimloc, "NIMLOC" }, // 32,	/*%< Nimrod Locator. */
	{ns_t_srv, "SRV" }, // 33,		/*%< Server Selection. */
	{ns_t_atma, "ATMA" }, // 34,		/*%< ATM Address */
	{ns_t_naptr, "NAPTR" }, // 35,	/*%< Naming Authority PoinTeR */
	{ns_t_kx, "KX" }, // 36,		/*%< Key Exchange */
	{ns_t_cert, "CERT" }, // 37,		/*%< Certification record */
	{ns_t_a6, "A6" }, // 38,		/*%< IPv6 address (deprecated, use {ns_t_aaaa) */
	{ns_t_dname, "DNAME" }, // 39,	/*%< Non-terminal DNAME (for IPv6) */
	{ns_t_sink, "SINK" }, // 40,		/*%< Kitchen sink (experimentatl) */
	{ns_t_opt, "OPT" }, // 41,		/*%< EDNS0 option (meta-RR) */
	{ns_t_apl, "APL" }, // 42,		/*%< Address prefix list (RFC3123) */
	{ns_t_tkey, "TKEY" }, // 249,	/*%< Transaction key */
	{ns_t_tsig, "TSIG" }, // 250,	/*%< Transaction signature. */
	{ns_t_ixfr, "IXFR" }, // 251,	/*%< Incremental zone transfer. */
	{ns_t_axfr, "AXFR" }, // 252,	/*%< Transfer zone of authority. */
	{ns_t_mailb, "MAILB" }, // 253,	/*%< Transfer mailbox records. */
	{ns_t_maila, "MAILA" }, // 254,	/*%< Transfer mail agent records. */
	{ns_t_any, "ANY" }, // 255,		/*%< Wildcard match. */
	{ns_t_zxfr, "ZXFR" }, // 256,	/*%< BIND-specific, nonstandard. */
	{ns_t_max, "MAX" }, // 65536
};

rcode_str rcode2str[]={
    {ns_r_noerror, "NOERROR"}, //0, < No error occurred. 
    {ns_r_formerr, "FORMERR"}, //1,    Format error. 
    {ns_r_servfail, "SERVFAIL"}, // = 2,  /*%< Server failure. */
    {ns_r_nxdomain, "NXDOMAIN"}, // = 3,  /*%< Name error. */
    {ns_r_notimpl, "NOTIMPL"}, // = 4,   /*%< Unimplemented. */
    {ns_r_refused, "REFUSED"}, // = 5,   /*%< Operation refused. */
    /* these are for BIND_UPDATE */
    {ns_r_yxdomain, "NAME_EXIST"}, // = 6,  /*%< Name exists */
    {ns_r_yxrrset, "RREXIST"}, // = 7,   /*%< RRset exists */
    {ns_r_nxrrset, "RRSETNOTEXIT"},// = 8,   /*%< RRset does not exist */
    {ns_r_notauth, "NOTAUTO"}, // = 9,   /*%< Not authoritative for zone */
    {ns_r_notzone, "NOTZONE"}, //= 10,  /*%< Zone of record different from zone section */
    {ns_r_max,     "MAX" }, //= 11,
    /* The following are EDNS extended rcodes */
    {ns_r_badvers, "BADVERS"},  //= 16,
    /* The following are TSIG errors */
    {ns_r_badsig, "BADSIG"}, // = 16,
    {ns_r_badkey, "BADKEY"}, // = 17,
    {ns_r_badtime , "BADTIME"}, //18
    {256, "UNKNOWN"}

};

char *rcodeStr[ns_t_max];
char rrtypeStr[ns_t_max][10];
int init_rcodeStr()
{
    int i;
    for (i =0; i <=257; i++)
    {
        rcodeStr[i] = unknown; 
    }  

    int cnt = sizeof(rcode2str)/sizeof(rcode2str[0]);
    for (i=0; i< cnt ; i++)
    {
       rcodeStr[rcode2str[i].rcode] = rcode2str[i].str; 
    } 
    return 0;
}

int init_rrtypeStr()
{
    int i;
    for (i =0; i <=ns_t_max; i++)
    {
        //char * ptr=malloc(10); 
        sprintf(rrtypeStr[i], "%d", i);
        //rrtypeStr[i] = ptr; //unknown; 
    }  

    int cnt = sizeof(rrtype2str)/sizeof(rrtype2str[0]);
    for (i=0; i< cnt ; i++)
    {
       //free(rrtypeStr[rrtype2str[i].rrtype] );
       strcpy(rrtypeStr[rrtype2str[i].rrtype], rrtype2str[i].str); 
    } 
    return 0;
}
 
/*
int free_rrtypeStr()
{
    int i;
    for (i =0; i <=ns_t_max; i++)
    {
        char * ptr=malloc(10); 
        sprintf(ptr, "%d", i);
        rrtypeStr[i] = ptr; //unknown; 
    }  

}
*/

char * str_rcode(int rcode)
{
/*
    int i;
    for (i=0; i < sizeof(rcode2str); i ++)
    {
        if (rcode2str[i].rcode == rcode )
            return rcode2str[i].str;
    }
    return rcode2str[sizeof(rcode2str)-1].str;
*/
   if (rcodeStr[rcode] ) 
        return rcodeStr[rcode];
    else 
        return unknown;
}

char * str_rrtype(int rrtype)
{
/*
    int i;
    for (i=0; i < sizeof(rrtype2str); i ++)
    {
        fprintf(stderr, "num:%d, type:%d , str:%s \n", 
                    i, rrtype2str[i].rrtype, rrtype2str[i].str);
        if (rrtype2str[i].rrtype == rrtype )
            return rrtype2str[i].str;
    }

    return rrtype2str[sizeof(rrtype2str) - 1].str;
*/
   if (rrtypeStr[rrtype] ) 
        return rrtypeStr[rrtype];
    else 
        return unknown;
}

int main(int argc, char * argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    int oc; // for command line parameters
    int count = -1; //number of packets to be analyzed, default: -1 (no count limitation)

    char bpf_program_str[] = "udp port 53";
    outh=stdout;
    logh=stderr; 

    if( argc <2)
    {
        usage(argv[0]);
        exit (1);
    }
    //input=argv[1];
    while( ( oc=getopt(argc, argv, "c:hi:l:o:")) != -1 )
    {
        switch (oc)
        {
            case 'c':
                count =  (int)strtol(optarg, (char **)NULL, 10);
                if(errno == EINVAL || errno == ERANGE )
                {
                    fprintf(stderr, "erro number of threads:%s\n", optarg );
                    return -1;
                }
            break;

            case 'h':
                    usage(argv[0]);
            break;
        
            case 'i':
                list_file = strdup(optarg);
                listh = fopen(list_file, "r");
                if (listh == NULL)
                {
                    fprintf(stderr, "Error: Can not open log file %s to read\n", list_file);
                    return -1;
                }
            break;

            case 'l':
                log_file = strdup(optarg);
                logh = fopen(log_file, "w");
                if (logh == NULL)
                {
                    fprintf(stderr, "Error: Can not open log file %s to write\n", log_file);
                    return -1;
                }
            break;
        
            case 'o':
                output_file = strdup(optarg);
                outh = fopen(output_file, "w");
                if (outh == NULL)
                {
                    fprintf(stderr, "Error: Can not open output file %s to write\n", output_file);
                    return -1;
                }
            break;
            
            default:
                usage(argv[0]);
            break;
 
        }
    }
    if (optind < argc - 1)
    {
        if(listh ==NULL) 
        {
            fprintf(stderr, "Error: input file needed\n");
            usage(argv[0]); 
        }
    }
    else
    {
        input_file = argv[optind];
    }
     
    tree = TrieInit();
    init_rrtypeStr();
    init_rcodeStr();

    int done=0; 
    int return_code = 0;
    FILE *fpcap=NULL;
    do {
        char filename[MAX_WORD];
        if( input_file )
        {
            strcpy(filename, input_file);
            done =1;
        } 
        else 
        {
            if( NULL == fgets(filename, MAX_WORD, listh))
                break; 
        }
        strtrim(filename);
        if ( NULL == (fpcap = fopen(filename, "r")))
        {
            fprintf(stderr, "Error on open pcap file\n");
            continue;
        }
        pcap = pcap_fopen_offline(fpcap, errbuf);
        if (NULL == pcap) {
            fprintf(stderr, "pcap_open_*: %s\n", errbuf);
            continue;
        }
        if ( 0>pcap_compile(pcap, &fp, bpf_program_str, 1, 0))
        {
            fprintf(stderr, "pcap_compile failed\n");
            continue;
        }
        if ( 0 > pcap_setfilter(pcap, &fp))
        {
            fprintf(stderr, "pcap_setfilter failed\n");
            continue;
        }
        if ( DLT_EN10MB != pcap_datalink(pcap) )
        {
            fprintf(stderr, "I cannot handle datalink other than Ethernet DLT_EN10MB\n");
            continue;
        }
        
        return_code = pcap_loop(pcap, count, my_callback, NULL); 
        if (return_code)
            fprintf(logh, "# return code:%d from file: %s \n", return_code, filename);
        fclose(fpcap);
    } while(! done) ;

    TrieTravelE(tree, outh);

    //fprintf(stderr, "press any key to release trie:\n");
    //getchar();

    if(tree)
        trie_free(tree);

    if(outh != stdout)
        fclose(outh);
    if(logh != stderr)
        fclose(logh);

    return return_code;
}
void usage(char *program)
{
    fprintf(stderr, "Usage: ./%s <pcap_file> \n", program);
    exit(1);
}

void my_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) 
{ 
    static int count = 1; 
    count++; 

    if (pkthdr->caplen < ETHER_HDR_LEN)
        return;
    timestamp = pkthdr->ts.tv_sec;
    fprintf(logh, "%ld.%ld ", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
    if (0 == handle_ether(packet, pkthdr->caplen))
        return;
}
int handle_ether(const u_char * pkt, int len)
{
    struct ether_header *e = (void *)pkt;
    unsigned short etype = ntohs(e->ether_type);
    if (len < ETHER_HDR_LEN)
    {
        fprintf(logh, "# ETHER HDR too short\n");
        return 0;
    }
    pkt += ETHER_HDR_LEN;
    len -= ETHER_HDR_LEN;
    #ifndef ETHERTYPE_8021Q
    #define ETHERTYPE_8021Q 0x8100
    #endif
    if (ETHERTYPE_8021Q == etype) 
    {
        etype = ntohs(*(unsigned short *)(pkt + 2));
        pkt += 4;
        len -= 4;
    }
    return handle_ip(pkt, len, etype);
}

int handle_ip(const u_char * pkt, int len, unsigned short etype)
{
#if USE_IPV6
    if (ETHERTYPE_IPV6 == etype) {
        return (handle_ipv6((struct ip6_hdr *)pkt, len));
    } else
#endif
    if (ETHERTYPE_IP == etype) {
        return handle_ipv4((struct ip *)pkt, len);
    }
    return 0;
}


int handle_ipv4(const struct ip *ip, int len)
{
    int offset = ip->ip_hl << 2;
    inX_addr src_addr;
    inX_addr dst_addr;

#if USE_IPV6
    if (ip->ip_v == 6)
        return (handle_ipv6((struct ip6_hdr *)ip, len));
#endif


/*
    if (0 == opt_count_ipv4)
    return 0;
*/

    memcpy (&ns_ip , &ip->ip_src, sizeof(long));

    inXaddr_assign_v4(&src_addr, &ip->ip_src);
    inXaddr_assign_v4(&dst_addr, &ip->ip_dst);

    char sbuf[1024],dbuf[1024];
    fprintf(logh, "%s %s ", inXaddr_ntop( &src_addr, sbuf, sizeof(sbuf)),
                              inXaddr_ntop( &dst_addr, dbuf, sizeof(dbuf)));

   // if (ignore_list_match(&src_addr))
    //return (0);

    if (IPPROTO_UDP != ip->ip_p)
        return 0;
    
    if (0 == handle_udp((struct udphdr *)((char *)ip + offset), len - offset, &src_addr, &dst_addr))
        return 0;
    return 1;
}


#if USE_IPV6
int handle_ipv6(struct ip6_hdr *ipv6, int len)
{
    int offset;
    int nexthdr;

    inX_addr src_addr;
    inX_addr dst_addr;
    uint16_t payload_len;

    if (0 == opt_count_ipv6)
	    return 0;

    offset = sizeof(struct ip6_hdr);
    nexthdr = ipv6->ip6_nxt;
    inXaddr_assign_v6(&src_addr, &ipv6->ip6_src);
    inXaddr_assign_v6(&dst_addr, &ipv6->ip6_dst);
    payload_len = ntohs(ipv6->ip6_plen);
/*
    if (ignore_list_match(&src_addr))
	return (0);
*/

    /*
     * Parse extension headers. This only handles the standard headers, as
     * defined in RFC 2460, correctly. Fragments are discarded.
     */
    while ((IPPROTO_ROUTING == nexthdr)	/* routing header */
	||(IPPROTO_HOPOPTS == nexthdr)	/* Hop-by-Hop options. */
	||(IPPROTO_FRAGMENT == nexthdr)	/* fragmentation header. */
	||(IPPROTO_DSTOPTS == nexthdr)	/* destination options. */
	||(IPPROTO_DSTOPTS == nexthdr)	/* destination options. */
	||(IPPROTO_AH == nexthdr)	/* destination options. */
	||(IPPROTO_ESP == nexthdr)) {	/* encapsulating security payload. */
	struct {
	    uint8_t nexthdr;
	    uint8_t length;
	}      ext_hdr;
	uint16_t ext_hdr_len;

	/* Catch broken packets */
	if ((offset + sizeof(ext_hdr)) > len)
	    return (0);

	/* Cannot handle fragments. */
	if (IPPROTO_FRAGMENT == nexthdr)
	    return (0);

	memcpy(&ext_hdr, (char *)ipv6 + offset, sizeof(ext_hdr));
	nexthdr = ext_hdr.nexthdr;
	ext_hdr_len = (8 * (ntohs(ext_hdr.length) + 1));

	/* This header is longer than the packets payload.. WTF? */
	if (ext_hdr_len > payload_len)
	    return (0);

	offset += ext_hdr_len;
	payload_len -= ext_hdr_len;
    }				/* while */

    /* Catch broken and empty packets */
    if (((offset + payload_len) > len)
	|| (payload_len == 0))
	return (0);

    if (IPPROTO_UDP != nexthdr)
	return (0);

    if (handle_udp((struct udphdr *)((char *)ipv6 + offset), payload_len, &src_addr, &dst_addr) == 0)
	return (0);

    return (1);			/* Success */
}
#endif

int
handle_udp(const struct udphdr *udp, int len, const inX_addr * src_addr, const inX_addr * dst_addr)
{
    if (0 == handle_dns((char *)(udp + 1), len - sizeof(*udp), src_addr, dst_addr))
        return 0;
    return 1;
}


int handle_dns(const char *buf, int len, const inX_addr * src_addr, const inX_addr * dst_addr)
{
    ns_msg handle;
    int rrnum; 
    ns_rr rr;
    int counts[4], i;
    int sections[]={ns_s_qd, ns_s_an, ns_s_ns, ns_s_ar};

    ns_initparse((u_char *)buf, len, &handle); 
    counts[0]=ns_msg_count(handle, ns_s_qd);
    counts[1]=ns_msg_count(handle, ns_s_an);
    counts[2]=ns_msg_count(handle, ns_s_ns);
    counts[3]=ns_msg_count(handle, ns_s_ar);

    authoritative = ns_msg_getflag(handle, ns_f_aa);
    recursive_desired = ns_msg_getflag(handle, ns_f_rd);
/*Format sample :
  1387727983.991160 202.38.193.33 118.67.114.9  NOERROR T 1 1 2 3|product.xgo.com.cn A|product.xgo.com.cn A 300  117.79.92.116 |xgo.com.cn NS 300  ns1.cnmo.com  ns.cnmo.com 
*/
    //char sbuf[1024],dbuf[1024];
/*
    fprintf(logh, "%s %s ", inXaddr_ntop( src_addr, sbuf, sizeof(sbuf)),
                              inXaddr_ntop( dst_addr, dbuf, sizeof(dbuf)));
*/
    fprintf(logh, "%s %c %c",  // %s %c 
        str_rcode(ns_msg_getflag(handle, ns_f_rcode)),
        TRUE_FALSE(authoritative),
        TRUE_FALSE(recursive_desired)
    );
    fprintf(logh, " %d %d %d %d %d", 
             counts[0], counts[1],counts[2], counts[3] , len);


    if( counts[0] <=0) 
    {
        //fprintf(outh, " !!: No query, len= %d\n", len);
        fprintf(logh, "# !!: No query, len= %d\n", len);
        return 0;
    }

    for ( i=0; i<4; i++)
    {
        if (counts[i])
        {
            for(rrnum = 0; rrnum < ns_msg_count(handle, sections[i]); rrnum++)
            { 
                if (ns_parserr(&handle, sections[i], rrnum, &rr)) 
                {
                    //fprintf(outh, " !!: ns_parserr: %s\n", strerror(errno));
                    fprintf(logh, "# !!: ns_parserr: %s\n", strerror(errno));
                    return 0;
                }
                else
                {
                    //if( i == 0 || rrnum == 0)
                    //fprintf(outh,"%s %d ", ns_rr_name(rr), ns_rr_type(rr) ); //%s %s 
                    qname = ns_rr_name(rr);
                    fprintf(logh,"|%s %s ", qname, str_rrtype(ns_rr_type(rr)) ); 

                    //if( ns_rr_rdlen(rr) ) 
                    if(i) // i=0  means this rr is in query section  
                        rr_display(&handle, rr, i);
                    /*
                    else // qd section
                    {
                        fprintf(outh, "|");
                    }
                    */
                }
            }
        }
    }
    fprintf(logh, "\n");

    return 1;
}

int escape_0d0a( char * src,  char *dst, int sizeofdst)
{
    //int len =0;
    char *ps, *pd;
    ps=src;
    pd=dst;
    while ( *ps  && (pd-dst)< sizeofdst ) 
    {
        if( *ps == '\r')
        {
           strncpy(pd,"\r",2);
           pd += 2; 
        }
        else if( *ps == '\n')
        {
           strncpy(pd,"\n",2);
           pd += 2; 
        }
        else if( *ps == '|')
        {
           *pd ='`'; // | is a seperator
           pd += 1; 
        }
        else 
        {
            *pd = *ps;
            pd += 1; 
        }
        ps++;
    } 
    return 0; 
}
int rr_display(ns_msg * handle, ns_rr rr , ns_sect section)
{
    char buff[1024], dispStr[2048], *rdata;
    long extFlags;
    unsigned short do_bit;
    int type=ns_rr_type(rr);
    u_char *ptr; 
    long ttl;
    int len;
    int tlen=0;
    int trie=0;
    ttl = ns_rr_ttl(rr);
    fprintf(logh,"%ld ", ttl ); // TTL for most RR; extended flags for OPT(EDNS0)

    trie=0;
    switch (type)
    {
       case ns_t_a:
            ptr = (u_char *) ns_rr_rdata(rr);
            rdata=(char *)ptr;
            len = ns_rr_rdlen(rr); 
            if ( NULL == inet_ntop(AF_INET, ptr, buff, sizeof(buff)))  
            {
                fprintf(logh, "# errono:%d", errno);
                return -1;
            }
            fprintf(logh, "%s ",  buff);  
            // add to trie:
            // long ns_ip, long ttl, long ip 
            trie =1;
        break; 
       case ns_t_ns:
            if (ns_name_uncompress( ns_msg_base(*handle), ns_msg_end(*handle), 
                ns_rr_rdata(rr), buff, sizeof(buff)) < 0) 
            {    
                (void) fprintf(logh, "# ns_name_uncompress failed\n");
                return -1;
            }
            fprintf(logh, "%s ", buff);
            rdata=buff;
            len = strlen(buff);
            // add to trie:
            // ns_ip, long ttl,  buff 
            trie =1;
        break; 
        case ns_t_ptr:
            len=get_name(handle, &rr, 0, buff, sizeof(buff)); 
            tlen =tlen +len;
            fprintf(logh, "%s ", buff);
            rdata = buff;
            len = strlen(buff);
            // add to trie:
            // ns_ip, long ttl,  buff 
            trie =1;
        break;
        case ns_t_soa:  //nnlll
            
            ptr=(u_char *) ns_rr_rdata(rr);
            tlen=0;
            len=get_name(handle, &rr, tlen, buff, sizeof(buff)); 
            fprintf(logh, "%s ", buff);
            
            tlen =tlen +len;
            len=get_name(handle, &rr, tlen, buff, sizeof(buff)); 
            tlen =tlen +len;
            fprintf(logh, "%s ", buff);
            rdata = buff;

            int i;
            for( i=0; i<5; i++)
            {
                fprintf(logh, "%ld ", ns_get32(ptr+tlen));
                tlen = tlen +4;
            }
            
        break;

        case  ns_t_txt :  //= 16,  
            ptr=(u_char *) ns_rr_rdata(rr) +1 ;
            len = ns_rr_rdlen(rr);
            if (len > sizeof(buff) - 1 )
                len = sizeof(buff) - 1;
            strncpy(buff, (char *) ptr, len);
            buff[len-1]=0;
            escape_0d0a(buff, dispStr, sizeof(dispStr));
            fprintf(logh, "%d \"%s\" ", len, dispStr); 
            rdata = dispStr;
            trie =1;

        break;

        case ns_t_cname :  //ns_t_cname = 5,     < Canonical name. 
            len=get_name(handle, &rr, 0, buff, sizeof(buff)); 
            tlen =tlen +len;
            fprintf(logh, "%s ", buff);
            rdata =  buff;
            len = strlen(buff);
            trie =1;
        break;
        case ns_t_mb :     // = 7,        %< Mailbox domain name. 
    
        break;

        case ns_t_mx : // = 15, 
            ptr=(u_char *) ns_rr_rdata(rr);
            tlen=0;
            fprintf(logh, "%ld ", ns_get32(ptr));
            tlen = tlen + 2;

            len=get_name(handle, &rr, tlen, buff, sizeof(buff)); 
            fprintf(logh, "%s ", buff);
            rdata = buff;
            len =  strlen(buff);
            
        break;

        case ns_t_opt: // = 41, 
            /* RFC 2671
             Field Name   Field Type     Description
                 ------------------------------------------------------
                 NAME         domain name    empty (root domain)
                 TYPE         u_int16_t      OPT
                 CLASS        u_int16_t      sender's UDP payload size
                 TTL          u_int32_t      extended RCODE and flags
                 RDLEN        u_int16_t      describes RDATA
                 RDATA        octet stream   {attribute,value} pairs
            */
            extFlags = ns_rr_ttl(rr);
            do_bit = ( extFlags & 0X08000) ? 1:0;
            fprintf(logh, "%d ", ns_rr_class(rr)); // sender's UDP size
            fprintf(logh, "%d ", ns_rr_rdlen(rr)); // length of rdata 
            if(do_bit) 
                fprintf(logh, "DO "); // length of rdata 
            else
                fprintf(logh, "DN "); // length of rdata 
            

            trie=0;
        break;

        case ns_t_aaaa: // = 28,     /*%< Ip6 Address. */
            ptr = (u_char *) ns_rr_rdata(rr);
            //len = ns_rr_rdlen(rr); 
            if ( NULL == inet_ntop(AF_INET6, ptr, buff, sizeof(buff)))  
            {
                fprintf(logh, "# errono:%d", errno);
                return -1;
            }
            fprintf(logh, "%s ",  buff);  
            len = strlen(buff);
            rdata = buff;
            trie = 1;
            
        break;

        case ns_t_any : //= 255, 
        break;

        default:
            //fprintf(logh, "unknow ns_type");
            //return 1;
        break;
    } 
    
    if( trie  && authoritative && section != ns_s_ar )
    {
        //char strIP[MAX_WORD];
        //fprintf(stderr, "ns_ip: %d %x (%s)\n",sizeof(ns_ip), ns_ip, inet_ntop(AF_INET, &ns_ip, strIP, sizeof(strIP)));
        pdata = rrdata_init(timestamp, type, ns_ip, ttl, len, rdata, authoritative);
        if(pdata)
        { 
            char r_name_t[MAX_WORD], r_name[MAX_WORD];
            r_name_t[0] = type; 
            r_name_t[1] = 0;
            strcat(r_name_t, qname);
            strReverse(r_name_t, r_name);
            TrieAdd(&tree, r_name, type, pdata);
        }
    }
    //fprintf(logh, "\n");
    return 0;
}

int get_name( ns_msg *handle, ns_rr *rr, int offset, char *buff, int size_of_buff )
{
        u_char *ptr=(u_char *)ns_rr_rdata(*rr) + offset;
        int len;
        
        if (( len=ns_name_uncompress( ns_msg_base(*handle), ns_msg_end(*handle), ptr, buff, size_of_buff))  < 0) 
        {    
            (void) fprintf(logh, "# ns_name_uncompress failed\n");
            return -1;
        }
       return len; 
}

