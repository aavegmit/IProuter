#ifndef _ROUTING_TABLE_H
#define _ROUTING_TABLE_H

#include <iostream>
#include <string>
#include <map>

using namespace std ;

typedef struct routerInfoT {
    string mac;
    string interface;
} routerInfo ;

extern map<string, routerInfo> macLookUp ;

#endif
