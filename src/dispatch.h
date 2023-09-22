#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>
#include "sniff.h"

void closeThreads(malicious_counter *sum);

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose, LinkedList *SYN_IPs);

typedef struct packetnode
{ // data structure for each node
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    struct packetnode *next;
} packetnode;

typedef struct packetqueue
{ // data structure for queue
    packetnode *head;
    packetnode *tail;
    int size;
    int v; // stores the verbose flag
} packetqueue;

packetqueue *create_queue(int verbose);

int isempty(packetqueue *q);

void enqueue(packetqueue *q, struct pcap_pkthdr *tmp_header, const unsigned char *tmp_packet);

void dequeue(packetqueue *q);

void destroy_queue(packetqueue *q);

extern void initCounters(malicious_counter *a);
void addCounters(malicious_counter *a, malicious_counter *b);
void *handle_thread();
void create_threads(int verbose);
void addCounters(malicious_counter *a, malicious_counter *b);
extern void sig_handler(int signo);

extern pthread_mutex_t list_lock;
#endif
