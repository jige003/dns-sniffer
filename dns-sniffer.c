/*************************************************************************
    > File Name: redis-sniffer.c
    > Author: jige003
 ************************************************************************/
#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <time.h>
#include <signal.h>
#include <hiredis/hiredis.h>
#include <hiredis/read.h>

#define TCP_OFF(tcp) (tcp->doff*sizeof(uint32_t))

#define IP_HL(ip) ((4*ip->ip_hl))

#define dbg(fmt, ...) \
    do {\
        if (debug) {\
            fprintf(stderr, "\033[0;32m[+] "fmt, ##__VA_ARGS__); \
            fprintf(stderr, "\033[0m");\
        }\
    }while(0);

int debug = 0;
int sport = 0;
int dport = 0;

char tmpfp[256] = {0};
char sip[20] = {0};
char dip[20] = {0};

struct {
    char *device;
    char bufstr[256];
    int port;
}option = {
    .device = NULL,
    .bufstr = {0}, 
    .port = 53
};

struct query_zone{
    u_char *name;
    uint16_t qtype;
    uint16_t class;
};


/**
 * DNS header
 */
struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} __attribute__((packed));

/**
 * Basic DNS record types (RFC 1035)
 */
static const char *dns_types[] = {
    "UNKN",  /* Unsupported / Invalid type */
    "A",     /* Host Address */
    "NS",    /* Authorative Name Server */
    "MD",    /* Mail Destination (Obsolete) */
    "MF",    /* Mail Forwarder   (Obsolete) */
    "CNAME", /* Canonical Name */
    "SOA",   /* Start of Authority */
    "MB",    /* Mailbox (Experimental) */
    "MG",    /* Mail Group Member (Experimental) */
    "MR",    /* Mail Rename (Experimental) */
    "NULL",  /* Null Resource Record (Experimental) */
    "WKS",   /* Well Known Service */
    "PTR",   /* Domain Name Pointer */
    "HINFO", /* Host Information */
    "MINFO", /* Mailbox / Mail List Information */
    "MX",    /* Mail Exchange */
    "TXT",   /* Text Strings */
    "AAAA"   /* IPv6 Host Address (RFC 1886) */
};

void Usage();

void px (char *tag, struct query_zone* qz);

char* getTimeNow();

pcap_t* init_pcap_t(char* device, const char* bpfstr);

void sniff_loop(pcap_t* pHandle, pcap_handler func);

void packetHandle(u_char* arg, const struct pcap_pkthdr* header, const u_char* pkt_data);

void bailout(int signo);

void printData(const char *data, int len);

void free_query_zone(struct query_zone *p);

int query_zone_parser(const u_char* pkt_data, unsigned int data_len, struct query_zone* qz);

int dns_query_parser(const u_char* pkt_data, unsigned int data_len);

int string2int(char *str);

int isstr(char *str, int len);


void xfree(void *ptr);

void Usage(){
    fprintf(stderr, "Copyright by jige003\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\tdns-sniffer [-h] -i interface -p port\n\n");
}

char* getTimeNow(){
    time_t tim;
    struct tm *at;
    static char now[80];
    time(&tim);
    at=localtime(&tim);
    strftime(now,79,"%Y-%m-%d %H:%M:%S",at);
    return now;
}


void px (char *tag, struct query_zone* qz) {
    fprintf(stdout, "%s  %s:%d -> %s:%d [ %s ] %s %s\n",getTimeNow(), sip, sport, dip, dport, tag, dns_types[qz->qtype], qz->name);
}

pcap_t* init_pcap_t(char* device, const char* bpfstr){
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *pHandle;

    uint32_t  srcip, netmask = -1;
    struct bpf_program bpf;

    if(!*device && !(device = pcap_lookupdev(errBuf))){
        printf("pcap_lookupdev(): %s\n", errBuf);
        return NULL;
    }

    printf("[*] sniffe on interface: %s\n", device);
    
    if((pHandle = pcap_open_live(device, 65535, 1, 0, errBuf)) == NULL){
        printf("pcap_open_live(): %s\n", errBuf);
        return NULL;
    }


    if (pcap_compile(pHandle, &bpf, (char*)bpfstr, 0, netmask)){
        printf("pcap_compile(): %s\n", pcap_geterr(pHandle));
        return NULL;
    }

    if (pcap_setfilter(pHandle, &bpf) < 0){
        printf("pcap_setfilter(): %s\n", pcap_geterr(pHandle));
        return NULL;
    }
    return pHandle;
}

void bailout(int signo){
    printf("ctr c exit\n");
    exit(0);
}

void sniff_loop(pcap_t* pHandle, pcap_handler func){
    int linktype, linkhdrlen=0;
 
    if ((linktype = pcap_datalink(pHandle)) < 0){
        printf("pcap_datalink(): %s\n", pcap_geterr(pHandle));
        return;
    }
    //printf("%d\n", linktype);
    switch (linktype){
    case DLT_RAW:
        linkhdrlen = 0;
        break;
        
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
    
    case DLT_LINUX_SLL:
        linkhdrlen = 16;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }
 
    if (pcap_loop(pHandle, -1, func, (u_char*)&linkhdrlen) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pHandle));   
    
}

void printData(const char *data, int len){
    int i = 0;
    for (; i < len; ++i ){
        char c = *(data+i);
        if (isprint(c)){
            printf("%c", c);
        }else{
            printf(".");
        }
    }
    printf("\n");
}

int string2int(char *str){
    char flag = '+';
    long res = 0;
    
    if(*str=='-')
    {
        ++str; 
        flag = '-'; 
    } 
    
    sscanf(str, "%ld", &res);
    if(flag == '-')
    {
        res = -res;
    }
    return (int)res;
}

int isstr(char *str, int len) {
    int f = 1;
    for(int i = 0; i < len; i++){
        if (!isprint(str[i])){
            f = 0;
            break;
        }
    }
    return f;
}


void xfree(void *ptr) {
    if (ptr != NULL) 
        free(ptr);
}

void free_query_zone(struct query_zone *p){
    if (!p->name)
        xfree(p->name);
}

int query_zone_parser(const u_char* pkt_data, unsigned int data_len, struct query_zone* qz) {
    const u_char* p = pkt_data;
    const u_char* end = pkt_data + data_len;
    dbg("query_zone_parser data_len:%d\n", data_len);
    u_char *name = (u_char*)malloc(sizeof(u_char) * 1024) ;
    memset(name, 0, 1024);
    u_char *dst = name;
    for(; *p; ) {
        memcpy(dst, p + 1, *p);
        dbg("len:%d name:%s \n", *p, dst);
        dst += *p;
        p += *p + 1;
        dbg("p:%p end:%p\n", p, end);
        if (p > end )
            goto err;
        *dst = '.';
        dst++;
    }
    
    *(--dst) = '\0';
    uint16_t qtype =  ntohs(*( (uint16_t *) ++p) );
    if (qtype == 28)
        qtype = 17;
    else if(qtype > 16)
        qtype = 0;
    uint16_t class = ntohs(*( (uint16_t *) (p + 2)) );
    dbg("name: %s qtype:%d class:%d \n", name, qtype, class);
    qz->name = name;
    qz->qtype = qtype;
    qz->class = class;
    return 0;

err:
    return 1;
}

int dns_query_parser(const u_char* pkt_data, unsigned int data_len){
    struct dnshdr* pdhdr;
    int offset;
    pdhdr = (struct dnshdr*) pkt_data;
    offset = sizeof(struct dnshdr);
    pkt_data += offset;
    dbg("pdhdr->ancount:%d pdhdr->qdcount:%d offset:%d trans id:%p\n", ntohs(pdhdr->ancount), ntohs(pdhdr->qdcount), offset, pdhdr->id);
    if (!pdhdr->ancount && !pdhdr->qdcount)
        goto err;

    
    struct query_zone* qz =  (struct query_zone*)malloc(sizeof(struct query_zone));
    memset(qz, 0, sizeof(struct query_zone));
    query_zone_parser(pkt_data, data_len-offset, qz);   
    dbg("qz=> name: %s qtype:%d class:%d \n", qz->name, qz->qtype, qz->class);
    
    px("query", qz);
    
    free_query_zone(qz);
    
    return 0;
err:
    return 1;
}

void packetHandle(u_char* arg, const struct pcap_pkthdr* header, const u_char* pkt_data){
    int *linkhdrlen = (int*) arg;
    unsigned int data_len,  r;
    struct ether_header* pehdr;
    struct ip* piphdr;
    struct tcphdr* ptcphdr;
    struct udphdr* pudphdr;

    if ( !pkt_data ){
        printf ("Didn't grab packet!/n");
        exit (1);
    }
    if (header->caplen < header->len) return;
    pehdr = (struct ether_header*)pkt_data;
    pkt_data += *linkhdrlen;
    
    piphdr = (struct ip*)pkt_data;
    pkt_data += IP_HL(piphdr);
    data_len = ntohs(piphdr->ip_len) - IP_HL(piphdr);
    strcpy(sip, inet_ntoa(piphdr->ip_src));
    strcpy(dip, inet_ntoa(piphdr->ip_dst));

    switch(piphdr->ip_p){
        case IPPROTO_TCP:
            ptcphdr = (struct tcphdr*)pkt_data;
            data_len = data_len - TCP_OFF(ptcphdr);
            pkt_data += TCP_OFF(ptcphdr);
            sport = ntohs(ptcphdr->source);
            dport = ntohs(ptcphdr->dest);
            dbg("type: tcp %s:%d => %s:%d data_len:%d pkt_data:%s\n", sip, sport, dip, dport, data_len, pkt_data);
            break;
        case IPPROTO_UDP:
            pudphdr = (struct udphdr*)pkt_data;
            data_len = data_len - sizeof(struct udphdr);
            pkt_data += sizeof(struct udphdr);
            sport = ntohs(pudphdr->source);
            dport = ntohs(pudphdr->dest);
            dbg("type: udp %s:%d => %s:%d data_len:%d pkt_data:%s\n", sip, sport, dip, dport, data_len, pkt_data);
            break;
        default:
            data_len = 0;
            pkt_data = NULL;
            break;
    }
    if (!data_len || !pkt_data ) 
        return;
    
    if (dport == option.port) {
        dbg("dns query  parser\n");
        dns_query_parser(pkt_data, data_len);   
    }

    signal(SIGINT, bailout);
    signal(SIGTERM, bailout);
    signal(SIGQUIT, bailout);
}   


int main(int argc, char **argv){
    char *device;
    char bpfstr[256] = "port 53";

    pcap_t* pHandle;
    
    int i;
    
    if (argc < 2 ){
        Usage();
        return -1;
    }

    while ((i = getopt(argc, argv, "hi:p:")) != -1) {
        switch(i){
            case 'h':
                Usage();
                return -1;
                break;
            case 'i':
                option.device = optarg;
                break;
            case 'p':
                option.port = atoi(optarg);
                break;
            default:
                break;
        }
    }

    sprintf(option.bufstr, "port %d", option.port);

    char *d = getenv("jdebug");
    if ( d != NULL &&  !strcmp(d, "true")) 
        debug = 1;
    
    dbg("debug mode\n");

    if((pHandle = init_pcap_t(option.device, option.bufstr))){
        sniff_loop(pHandle, (pcap_handler)packetHandle);
    }    
    exit(0);

}

