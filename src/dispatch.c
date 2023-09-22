#include "dispatch.h"
#include <pcap.h>

#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <signal.h>
#include <pthread.h>
// the number of threads that we use
#define ThreadNumber 2
// the queue for the Threadpool
packetqueue *thrplq;
// two total threads in the Threadpool
pthread_t threads[ThreadNumber];
/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;

static counter = 0;

// indicates for the threads to know that they should be running
int isRunning = 1;
int threadsWork = 0;

LinkedList *ipList;
int mycounter = 0;
static int verb = 0;

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose, LinkedList *SYN_IPs)
{
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.

  // acquire lock
  pthread_mutex_lock(&queue_mutex);
  // copy the SYN_IPs pointer to a globale variable inside this file
  ipList = SYN_IPs;
  // add packet to queue
  enqueue(thrplq, header, packet);
  verb = verbose;
  // release lock
  pthread_mutex_unlock(&queue_mutex);
}

/**
 * @brief
 *
 * @return void*
 */
void *handle_thread()
{
  malicious_counter *threadcnt;
  // Initialise the counters of the current thread
  threadcnt = (malicious_counter *)malloc(sizeof(struct malicious_counter));
  initCounters(threadcnt);
  if (threadcnt == NULL)
    return NULL;
  // While the programm is running
  while (isRunning)
  {
    int verbose1;
    // Acquire lock to access queue and check whether or not it is empty
    pthread_mutex_lock(&queue_mutex);
    if (!isempty(thrplq))
    {
      verbose1 = verb;
      packetnode *tempPacket = malloc(sizeof(struct packetnode));
      tempPacket = thrplq->head;
      // Remove packet from the queue
      dequeue(thrplq);
      // release lock
      pthread_mutex_unlock(&queue_mutex);
      malicious_counter *tempCnt;
      // Initialize the counter for the current packet before it will be passed on
      // to be analysed with the analyse() function
      tempCnt = (malicious_counter *)malloc(sizeof(struct malicious_counter));
      analyse((struct pcap_pkthdr *)tempPacket->header, (const unsigned char *)tempPacket->packet, verbose1, ipList, tempCnt);
      // Adding all the packet counters to the thread counter
      addCounters(threadcnt, tempCnt);
      // free the memory location for the dequeued element and the temporary Counter
      // free((void *)tempPacket->packet);
      free(tempPacket->packet);
      free(tempPacket->header);
      free(tempPacket);
      free(tempCnt);
    }
    else
    {
      pthread_mutex_unlock(&queue_mutex);
    }
  }
  // returns the counters of the thread
  return ((void *)threadcnt);
}

/**
 * @brief Create all the threads that the program will have
 *
 * @param verbose
 */
void create_threads(int verbose)
{
  threadsWork = 1; // raise flag to indicate that Threads are set up
  thrplq = create_queue(verbose);
  int j;
  for (j = 0; j < ThreadNumber; j++)
    pthread_create(&threads[j], NULL, &handle_thread, NULL);
}

// closing the threads and returns a variable of the final counters
void closeThreads(malicious_counter *sum)
{
  isRunning = 0;
  initCounters(sum);
  if (threadsWork)
  {
    int j;
    int err;
    threadsWork = 0;
    for (j = 0; j < ThreadNumber; j++)
    {
      malicious_counter *temp;
      err = pthread_join(threads[j], (void **)&temp);
      if (err != 0)
        error(err, "pthread_join");
      malicious_counter *threadCounter = (malicious_counter *)malloc(sizeof(struct malicious_counter));
      threadCounter = (malicious_counter *)temp;
      // Adding all the thread counters to the final counter
      addCounters(sum, threadCounter);
      free(threadCounter);
    }
  }
  destroy_queue(thrplq);
  free(thrplq);
}

packetqueue *create_queue(int verbose)
{ // creates a queue and returns its pointer
  packetqueue *q = (packetqueue *)malloc(sizeof(packetqueue));
  if (q == NULL)
    exit(1);
  q->head = NULL;
  q->tail = NULL;
  q->v = verbose;
  q->size = 0;
  return q;
}

void destroy_queue(packetqueue *q)
{ // destroys the queue and frees the memory
  while (!isempty(q))
  {
    packetnode *temp = q->head;

    dequeue(q);
    free((void *)temp->packet);
    free(temp);
  }
  pthread_mutex_destroy(&queue_mutex);
  pthread_mutex_destroy(&list_lock);
}

int isempty(packetqueue *q)
{ // checks if queue is empty
  return (q->head == NULL);
}

void enqueue(packetqueue *q, struct pcap_pkthdr *tmp_header, const unsigned char *tmp_packet)
{ // enqueues a node with an item
  packetnode *new_node = (packetnode *)malloc(sizeof(packetnode));
  if (new_node == NULL)
    exit(1);
  // copy packet to heap memory
  unsigned char *new_packet = (unsigned char *)malloc((sizeof(unsigned char) * (int)tmp_header->len) + 1);
  // Check if there is an error and the packet is NULL
  if (tmp_packet == NULL)
    exit(1);
  memcpy(new_packet, tmp_packet, tmp_header->len);
  new_packet[sizeof(char) * tmp_header->len] = '\0';

  // copy header to heap memory
  struct pcap_pkthdr *new_header = (struct pcap_pkthdr *)malloc(sizeof(struct pcap_pkthdr));
  // Check if there is an error and the header is NULL
  if (tmp_header == NULL)
    exit(1);
  memcpy(new_header, tmp_header, sizeof(tmp_header));
  new_node->header = new_header;
  new_node->packet = new_packet;
  new_node->next = NULL;

  if (isempty(q))
  {
    q->head = new_node;
    q->tail = new_node;
  }
  else
  {
    q->tail->next = new_node;
    q->tail = new_node;
  }
  q->size++;
}

/**
 * @brief removes the head of the queue but it doesn't free that pointer
 * since in this program it will be needed later
 * @param q
 */
void dequeue(packetqueue *q)
{ // dequeues a the head node
  packetnode *head_node;
  if (isempty(q))
  {
    printf("Error: attempt to dequeue from an empty queue");
  }
  else
  {
    head_node = q->head;
    q->head = q->head->next;
    if (q->head == NULL)
      q->tail = NULL;
    // We do not free this memory because it is the pakcet that we want to analyse next
    // We so we will free it right after it has been analysed
    // free(head_node);
    q->size--;
  }
}

/**
 * @brief Adds all the counters of the the second counter variable to the first
 *
 * @param a first counter
 * @param b second counter
 */
void addCounters(malicious_counter *a, malicious_counter *b)
{
  a->syn_attacks += b->syn_attacks;
  a->unique_syn_ips += b->unique_syn_ips;
  a->blacklisted_google += b->blacklisted_google;
  a->blacklisted_fb += b->blacklisted_fb;
  a->arp_attacks += b->arp_attacks;
}