#ifndef _WRITEPACKET_H
#define _WRITEPACKET_H

#include "parse_packet.h"
#include "sniffer.h"
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
#include <queue>
#include <sys/wait.h>
#include <ctype.h>
#include <pcap.h>

using namespace std;

extern list<packetInfo > sendQueue;
extern pthread_mutex_t mutex;
extern pthread_cond_t cv;


void* injectPacket(void *);
void packet_injection(u_char*, uint32_t, u_char *, int );

#endif

