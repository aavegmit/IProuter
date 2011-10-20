#ifndef _ROUTING_TABLE_H
#define _ROUTING_TABLE_H

#include <iostream>
#include <string>
#include <map>
#include <stdint.h>

using namespace std ;

typedef struct routerInfoT {
    uint8_t mac[6];
    string interface;
    uint8_t self_mac[6];
    string self_ip;
} routerInfo ;

typedef struct routerEntryT{

    unsigned char nextHopIP[4];

}routerEntry;

extern map<string, routerInfo> macLookUp ;
extern map<string, routerEntry> routingTable;
extern bool macLookUpDone;

void getNetworkAddress(unsigned char[], unsigned char*);
void populateRoutingTable();
void printRoutingTable();
#endif
