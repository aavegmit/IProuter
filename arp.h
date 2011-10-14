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

#include "routingTable.h"

void loadArpInfoInMemory() ;
string getArpFromKernel(char *, char *) ;

#endif
