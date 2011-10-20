#include "routingTable.h"
#include "stdio.h"

map<string, routerEntry> routingTable;

void getNetworkAddress(unsigned char dstIP[], unsigned char *networkAddress){

    printf("\nNetwork address inside function: %02x.%02x.%02x.%02x\n", dstIP[3], dstIP[2], dstIP[1], dstIP[0]);
    networkAddress[3] = dstIP[3] & 0xff;
    networkAddress[2] = dstIP[2] & 0xff;
    networkAddress[1] = dstIP[1] & 0xff;
    networkAddress[0] = 0;
}

void populateRoutingTable(){

    routingTable[string("10.1.0.0")].nextHopIP[0] = 0x01;
    routingTable[string("10.1.0.0")].nextHopIP[1] = 0x00;
    routingTable[string("10.1.0.0")].nextHopIP[2] = 0x63;
    routingTable[string("10.1.0.0")].nextHopIP[3] = 0x0a;
    
    routingTable[string("10.1.2.0")].nextHopIP[0] = 0x02;
    routingTable[string("10.1.2.0")].nextHopIP[1] = 0x00;
    routingTable[string("10.1.2.0")].nextHopIP[2] = 0x63;
    routingTable[string("10.1.2.0")].nextHopIP[3] = 0x0a;
}

void printRoutingTable(){    
    printf("Entries in Routing Table...\n");
    for(map<string, routerEntry>::iterator it = routingTable.begin();it!=routingTable.end(); it++){

        printf("Destination Network: %s\tNext Hop IP: ", (*it).first.c_str());
        for(int i=3;i>=0;i--){
            printf("%d.", (*it).second.nextHopIP[i]);
        }
        printf("\n");
    }
}
