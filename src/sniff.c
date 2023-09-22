#include "sniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>

pcap_t *pcap_handle;

static LinkedList *SYN_IPs;
static unsigned long num_packets = 0;

/**
 * @brief
 *
 * @param args includes every variable listed after the function name in the call
 *             in this program it only stores the verbose value that we pass.
 * @param header the pcap handle header that we get with the pcap_open_live() function call
 * @param packet a pointer to the beggining of the header of the packet
 */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{

  int verbose = (int)args[0];
  if (verbose)
    printf("=== PACKET %ld  ===", num_packets++);
  // call dispatch to allocate packet to one of the threads to be processed
  dispatch(header, packet, verbose, SYN_IPs);
}

// Application main sniffing loop
void sniff(char *interface, int verbose)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  // 1:  promisc specifies whether the interface is to be put into promiscuous mode.  If promisc is non-zero, promiscuous mode will be set, otherwise it will not be set.
  // 1000:to_ms specifies the packet buffer timeout, as a non-negative value, in  milliseconds.
  // errbuf : might contain somthing even if the return is not NULL-----
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL)
  {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  }
  else
  {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }

  struct pcap_pkthdr header;
  const unsigned char *packet;

  // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
  // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
  // See the man pages of both pcap_loop() and pcap_next().

  // while (1) {
  //   // Capture a  packet
  //   packet = pcap_next(pcap_handle, &header);
  //   if (packet == NULL) {
  //     // pcap_next can return null if no packet is seen within a timeout
  //     if (verbose) {
  //       printf("No packet received. %s\n", pcap_geterr(pcap_handle));
  //     }
  //   } else {
  //     // If verbose is set to 1, dump raw packet to terminal
  //     if (verbose) {
  //       dump(packet, header.len);
  //     }
  //     // Dispatch packet for processing
  //     dispatch(&header, packet, verbose);
  //   }
  // }

  // Check if there is a signal for Cntr+C
  if (signal(SIGINT, sig_handler) == SIG_ERR)
  {

    fputs("An error occurred while setting a signal handler.\n", stderr);
    exit(0);
  }

  // initialize the list that will store the Ips of the syn packets as long format
  SYN_IPs = (LinkedList *)malloc(sizeof(LinkedList));
  // Need to initialize the list before we use it
  initList(SYN_IPs);
  // Create threads
  create_threads();

  // start packet sniffing here
  // If pcap_loop() function returns -1 then it means that an error has occured and
  // it is useful to inform the user.
  // In this function call the second parameter that we pass is the -1, because we
  // want it to keep sniffing packets indefinitely until we terminate it.
  if (pcap_loop(pcap_handle, -1, got_packet, (unsigned char *)&verbose) == -1)
  {
    fprintf(stderr, "ERROR: %s\n", pcap_geterr(pcap_handle));
  }

  pcap_close(pcap_handle);
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length)
{
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *)data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i)
  {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5)
    {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i)
  {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5)
    {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0)
  {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i)
    {
      if (i < output_bytes)
      {
        printf("%02x ", payload[i]);
      }
      else
      {
        printf("   "); // Maintain padding for partial lines
      }
    }
    printf("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i)
    {
      char byte = payload[i];
      if (byte > 31 && byte < 127)
      {
        // Byte is in printable ascii range
        printf("%c", byte);
      }
      else
      {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
// Initializing the custom counting structure that we use
void initCounters(malicious_counter *a)
{
  a->arp_attacks = 0;
  a->blacklisted_fb = 0;
  a->blacklisted_google = 0;
  a->syn_attacks = 0;
  a->unique_syn_ips = 0;
}
/**
 * @brief
 *
 * @param signo it is the signal that was issued and it is represented as an integer
 */
void sig_handler(int signo)
{
  // If the signal is cntrl+c we want to output a brief review of the intrusion detection
  //  according to the packets that we have captured and terminate the program
  if (signo == SIGINT)
  {
    malicious_counter *total = malloc(sizeof(struct malicious_counter));
    closeThreads((malicious_counter *)total);
    int blacklist_sum = total->blacklisted_fb + total->blacklisted_google;
    printf("\n");
    printf("%d SYN  packets detected from %d different IPs (syn attack)\n", total->syn_attacks, SYN_IPs->size);
    printf("%d ARP responses (cache poisoning)\n", total->arp_attacks);
    printf("%d URL Blacklist violations (%d google and %d facebook)\n", blacklist_sum, total->blacklisted_google, total->blacklisted_fb);
    // Free the memory addresses that have been allocated
    freeList(SYN_IPs->head);
    free(total);
    free(SYN_IPs);
    printf("num_packets=%d/n", num_packets);
    if (pcap_handle)
      pcap_close(pcap_handle);
  }
  exit(1);
}
/*Initialising the array structure*/
void initList(LinkedList *l)
{
  l->head = NULL;
  l->size = 0;
}

void freeList(struct ListElement *head)
{
  struct node *tmp;

  while (head != NULL)
  {
    tmp = head;
    head = head->next;
    free(tmp);
  }
}