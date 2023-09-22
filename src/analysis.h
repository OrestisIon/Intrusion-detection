#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H
#include "sniff.h"
#include "dispatch.h"
#include <pcap.h>

/*Got this structure from: https://inst.eecs.berkeley.edu/~ee122/fa07/projects/p2files/packet_parser.c ,
 *accessed on 3/12/2022
 */
struct UDP_hdr
{
    u_short uh_sport; /* source port */
    u_short uh_dport; /* destination port */
    u_short uh_ulen;  /* datagram length */
    u_short uh_sum;   /* datagram checksum */
};

// void insert_toList(LinkedList *mylist, struct iphdr *ipheader);

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose, LinkedList *SYN_IPs, malicious_counter *packetcounter);
// void initArray(MyArray *a, const int initialSize);
// void insert_toArray(MyArray *a, const long element);
// void freeArray(MyArray *a);
void print_blacklisted(char *src, char *dest);
void printUDP(unsigned char *udp_packet, int capture_len);

#endif
