#include "analysis.h"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>

// FROM https://sites.uclouvain.be/SystInfo/usr/include/linux/if_arp.h.html
struct arppacket
{
  struct arphdr ea_hdr;
  // varible size- depending on ETH_ALEN
  uint8_t ar_sha[ETH_ALEN]; /* sender hardware address */
  uint8_t ar_sip[4];        /* sender IP address */
  uint8_t ar_tha[ETH_ALEN]; /* target hardware address */
  uint8_t ar_tip[4];        /* target IP address */
};
pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
const char *blacklisted[2] = {"www.google.co.uk", "www.facebook.com"};

/**
 * @brief adds source ip address of the packet to list.
 * Only adds IPs that don't already exist in the list
 * @param mylist the list that we want to add the new element in
 * @param ipheader the ip header of the packet
 */
void insert_toList(LinkedList *mylist, struct iphdr *ipheader)
{
  // if empty list
  if (mylist->head == NULL)
  {
    struct ListElement *temp = (struct ListElement *)malloc(sizeof(struct ListElement));
    temp->ip = (long)ipheader->saddr;
    temp->next = NULL;
    mylist->head = temp;
    mylist->size = 1;
    // printf("ip: %lu",  mylist->head->val);
    return;
  }
  else
  {
    struct ListElement *temp = mylist->head;
    while (temp->next != NULL)
    {
      if (temp->ip == (long)ipheader->saddr)
      {
        return;
      }
      temp = temp->next;
    }
    // check if the last element is equal to the one that we search for
    if (temp->ip == (long)ipheader->saddr)
      return;
    // add to list since does not exist
    struct ListElement *newElement = (struct ListElement *)malloc(sizeof(struct ListElement));
    newElement->ip = (long)ipheader->saddr;
    newElement->next = NULL;
    temp->next = newElement;
    mylist->size++;
  }
}

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose, LinkedList *SYN_IPs, malicious_counter *packetcounter)
{

  // TODO your part 2 code here
  initCounters(packetcounter);
  struct ether_header *eth_header;
  struct tcphdr *tcp_header;
  struct iphdr *ip_header;
  struct ip *ip_header2;
  static int notInitialized = 1;
  int dest_port;
  // size of the payload
  // int size_remaining = (header->caplen);

  int size_remaining = (int)(header->len);
  // if(verbose==1)
  //  dump(packet, (*header).len);
  /* define the ethernet header offset */
  eth_header = (struct ether_header *)packet;
  /* check to see if we have an ip packet */
  if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
  {
    if (verbose)
      printf("(/ IP /)\n");
  }
  // In case the packet is ARP type
  else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
  {
    struct arppacket *packet_arp = (struct arppacket *)(packet + ETH_HLEN);
    struct arphdr *arp_header = (struct arphdr *)&packet_arp->ea_hdr;
    if (verbose)
    {
      printf("\n(/ ARP /)");

      printf("Hardware type: %s\n", (ntohs(arp_header->ar_hrd) == 1) ? "Ethernet" : "Unknown");
      // Checks if it is IP
      printf("Operation: ");
      if (ntohs(arp_header->ar_op) == ARPOP_RREQUEST)
        printf("ARP Request\n");
      else
        printf("ARP Reply\n");
      int i;
      printf("Sender MAC(hardware address): ");
      for (i = 0; i < ETH_ALEN; i++)
        printf("%02X:", packet_arp->ar_sha[i]);

      printf("\nSender IP: ");
      for (i = 0; i < 4; i++)
        printf("%d.", packet_arp->ar_sip[i]);

      printf("\nTarget MAC(hardware address): ");
      for (i = 0; i < ETH_ALEN; i++)
        printf("%02X:", packet_arp->ar_tha[i]);

      printf("\nTarget IP: ");
      for (i = 0; i < 4; i++)
        printf("%d.", packet_arp->ar_tip[i]);

      printf("\n\n");
    }
    // If it is a Reply ARP
    if (ntohs(arp_header->ar_op) == ARPOP_REPLY)
    {
      // Detect ARP poisoning attack and increment counter
      packetcounter->arp_attacks++;
    }
    // Finished parsing ARP packet
    return;
  }
  else
  {
    if (verbose)
      printf("\n(/ ? /)");
  }
  // update the size to the remaining of the packet after the Ethernet Header
  size_remaining -= ETH_HLEN;
  /* define the ip header offset */
  ip_header = (struct iphdr *)(packet + ETH_HLEN);
  ip_header2 = (struct ip *)(packet + ETH_HLEN);
  int iphdr_size = (ip_header->ihl) * 4;
  // check if the IP header is the the least bits to be valid
  if (iphdr_size < 20 && iphdr_size != 0)
  {
    if (verbose)
      printf("   * Invalid IP header length: %u bytes\n", iphdr_size);
    return;
  }

  if (verbose)
  {
    printf("\nIP Header\n");
    printf("   /--Version of IP     : %d\n", (unsigned int)ip_header->version);
    printf("   /--IP Header Length  : %d Bytes\n", ((unsigned int)(ip_header->ihl)) * 4);
    printf("   /--Type Of Service   : %d\n", (unsigned int)ip_header->tos);
    printf("   /--IP Length   : %d  Bytes(Size of Packet)\n", ntohs(ip_header->tot_len));
    printf("   /--TTL      : %d\n", (unsigned int)ip_header->ttl);
    printf("   /--Checksum : %d\n", ntohs(ip_header->check));
    printf("   /--Identification    : %d\n", ntohs(ip_header->id));
    printf("   /--Source IP        : %s\n", inet_ntoa(ip_header2->ip_src));
    printf("   /--Destination IP   : %s\n", inet_ntoa(ip_header2->ip_dst));
  }
  // update the size to the remaining of the packet after the IP Header
  size_remaining -= iphdr_size;
  // Determine which protocol is used
  switch (ip_header->protocol)
  {
  case 1:
    if (verbose)
      printf("   Protocol: ICMP\n");
    return;
  case 2:
    if (verbose)
      printf("   Protocol: IGMP\n");
    return;
  case 6:
    if (verbose)
      printf("   Protocol: TCP\n");
    break;
  case 17:
    if (verbose)
    {
      unsigned char *temp_packet = packet + ETH_HLEN + iphdr_size;
      printUDP(temp_packet, size_remaining);
    }
    return;
  default:
    if (verbose)
      printf("   Protocol: unknown\n");
    return;
  }

  // If the protocol is TCP we need to check if has a SYN request
  tcp_header = (struct tcphdr *)(packet + ETH_HLEN + iphdr_size);
  int tcp_size = (tcp_header->th_off) * 4;
  if (tcp_size < 20)
  {
    if (verbose)
      printf("   * Invalid TCP header length: %u bytes\n", tcp_size);
    return;
  }

  dest_port = ntohs(tcp_header->th_dport);

  if (verbose)
  {
    printf("   Source port: %d\n", ntohs(tcp_header->th_sport));
    printf("   Destination port: %d\n", dest_port);
  }
  // Check if it is a SYN packet
  if (!tcp_header->urg && !tcp_header->ack && !tcp_header->rst && !tcp_header->fin && tcp_header->syn)
  {
    pthread_mutex_lock(&list_lock);
    // Add source IP address of the packet to the list of SynIps
    insert_toList(SYN_IPs, (struct iphdr *)ip_header);
    pthread_mutex_unlock(&list_lock);
    packetcounter->syn_attacks++;
  }

  // Check for blacklisted
  if (dest_port == 80)
  {
    /* define/compute tcp payload (segment) offset */
    const unsigned char *payload = (unsigned char *)(packet + ETH_HLEN + iphdr_size + tcp_size);
    /* compute tcp payload (segment) size */

    char *request = (char *)malloc(sizeof(char) * strlen(payload) + 1); // string that will store the payload
    request = payload;
    memcpy(request, payload, strlen(payload));
    request[strlen(payload)] = '\0';

    int j = 2;
    while ((--j) >= 0)
    {
      if (verbose)
        if (strstr(request, "POST") != NULL)
          printf("%s", request);
      if (strstr(request, "GET") != NULL)
        if (strstr(request, blacklisted[j]) != NULL)
        {
          if (verbose)
            printf("%s", request);
          print_blacklisted((char *)inet_ntoa(ip_header2->ip_src), (char *)inet_ntoa(ip_header2->ip_dst));

          if (j == 1)
            packetcounter->blacklisted_fb++;
          else
            packetcounter->blacklisted_google++;
        }
    }
  }
  return;
}

/*
  Function called to print on the screen that a blacklist URL has been found
*/
void print_blacklisted(char *src, char *dest)
{
  printf("==============================\n");
  printf("Blacklisted URL violation detected\n");
  printf("Source IP address:%s\n", (char *)src);
  printf("Destination IP address:%s\n", (char *)dest);
  printf("==============================\n");
}

/**
 * @brief Prints the udp header
 *
 * @param udp_packet
 * @param capture_len
 */
void printUDP(unsigned char *udp_packet, int capture_len)
{
  /*  Get the UDP header. */
  if (capture_len < sizeof(struct UDP_hdr))
  {
    // too_short(packet_ts, "UDP header");
    return;
  }

  struct UDP_hdr *udpheader = (struct UDP_hdr *)udp_packet;
  printf("   Protocol: UDP\n");
  printf("--------------\nSource Port=%d \nDestination Port=%d \nLength=%d\n--------------",
         ntohs(udpheader->uh_sport),
         ntohs(udpheader->uh_dport),
         ntohs(udpheader->uh_ulen));
}
