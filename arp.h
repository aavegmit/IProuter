#ifndef ARP_H
#define ARP_H

#include <iostream>
#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <list>
#include <sys/wait.h>
#include <ctype.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <linux/if_ether.h>

#include "routingTable.h"

#define ETH_HW_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_FRAME_TYPE 0x0806
#define ETHER_HW_TYPE 1
#define IP_PROTO_TYPE 0x0800
#define OP_ARP_REQUEST 2

struct arp_packet {
        u_char targ_hw_addr[ETH_HW_ADDR_LEN];
        u_char src_hw_addr[ETH_HW_ADDR_LEN];
        u_short frame_type;
        u_short hw_type;
        u_short prot_type;
        u_char hw_addr_size;
        u_char prot_addr_size;
        u_short op;
        u_char sndr_hw_addr[ETH_HW_ADDR_LEN];
        u_char sndr_ip_addr[IP_ADDR_LEN];
        u_char rcpt_hw_addr[ETH_HW_ADDR_LEN];
        u_char rcpt_ip_addr[IP_ADDR_LEN];
//        u_char padding[18];
};

void die(char *);
void get_ip_addr(struct in_addr*,char*);
int sendArpRequest(char *, char *) ;
void loadArpInfoInMemory() ;
string getArpFromKernel(char *, char *) ;
void populateSelfMac() ;

#endif
