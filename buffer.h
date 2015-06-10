#ifndef __BUFFER_H
#define __BUFFER_H

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

#include <string.h>
#include <string>
#include <map>
#include <iostream>
#define ETH_HSIZE sizeof(struct ethhdr)
#define IP_HSIZE sizeof(struct iphdr)
#define TCP_HSIZE sizeof(struct tcphdr)

#define ACCOUNT_EMPTY 0         /* have not found account */
#define ACCOUNT_RECEIVING 1     /* account receiving */
#define ACCOUNT_COMPLETED 2     /* receiving completed */
#define PASSWORD_RECEIVING 3
#define PASSWORD_COMPLETED 4
typedef struct __account
{
        std::string user;
        std::string passwd;
        int flag;
        void clear(){user.clear(); passwd.clear(); flag = 0;}
}account;
struct addr_cmp
{
        bool operator()(const struct sockaddr_in &l, const sockaddr_in &r) const
        {
                return l.sin_addr.s_addr < r.sin_addr.s_addr;
        }
};
typedef std::map<struct sockaddr_in, account, addr_cmp> tnpwbuf;

#include <string.h>
#include <pcap.h>
#include <stdlib.h>

#define DEFAULT_CAPACITY 65536
#define GARBAGE_SIZE (DEFAULT_CAPACITY/2)

/* an item in buffer contains packet header
 * and the full packet with additional info
 */
typedef struct  __item{

  struct pcap_pkthdr* packet_header;
  u_char* full_packet;  
  short int garbage; /* marked for collection */
  struct __item* prev; /* item in front */
  struct __item* next; /* next item */

}item;

/* buffer contains a doubly-linked list of items
 * and additional info
 */
typedef struct __buffer{

  long long int items; /* number of items currently in the list */
  long long int capacity; /* maximum capacity */
  long long int garbage_size; /* collect garbage when we hit this limit */

  item* header; /* head of the list */
  item* tail; /* tail of the list */

}buffer;

/* initialize the buffer */
int create_buffer(buffer*, long long int, long long int);

/* insert an item into the buffer */
int append_item(buffer*, const struct pcap_pkthdr*, const u_char*);

/* run garbage collection returns freed items */
int gc(buffer*);


int deal_packet(tnpwbuf* buf, const struct pcap_pkthdr* packet_header, const u_char* full_packet);

#endif
