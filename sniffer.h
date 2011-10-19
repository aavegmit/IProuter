#ifndef _SNIFFER_H
#define _SNIFFER_H

#include "parse_packet.h"
#include "routingTable.h"
#include "arp.h"
#include "config.h"

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

using namespace std ;

typedef struct snifferArgs{
    char interface[10];
    char expression[256];
}snifferArgs;

void* snifferThread(void *);

#endif
