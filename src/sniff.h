#ifndef CS241_SNIFF_H
#define CS241_SNIFF_H

void dump(const unsigned char *data, int length);
// void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void sniff(char *interface, int verbose);
// header for the signal handler function
void sig_handler(int signo);

typedef struct ListElement
{
    long ip;
    struct ListElement *next;
} ListElement;

typedef struct LinkedList
{
    struct listelement *head;
    int size;
} LinkedList;

typedef struct malicious_counter
{
    unsigned int syn_attacks;
    unsigned int unique_syn_ips;
    unsigned int arp_attacks;
    unsigned int blacklisted_fb;
    unsigned int blacklisted_google;
} malicious_counter;
// void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);
void initCounters(malicious_counter *a);
void initList(LinkedList *l);
extern void closeThreads(malicious_counter *sum);
void freeList(struct ListElement *head);

#endif
