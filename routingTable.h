#ifndef _ROUTING_TABLE_H
#define _ROUTING_TABLE_H

#include <iostream>
#include <string>
#include <map>

using namespace std ;

typedef struct routerInfoT {
    uint8_t mac[6];
    string interface;
    uint8_t self_mac[6];
    string self_ip;
} routerInfo ;

extern map<string, routerInfo> macLookUp ;
extern bool macLookUpDone;

#endif
