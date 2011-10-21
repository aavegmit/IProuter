#include "routingTable.h"
#include "stdio.h"

map<string, routerEntry> routingTable;

void getNetworkAddress(unsigned char dstIP[], unsigned char *networkAddress){

    uint32_t dstip[4];

    sscanf((char *)dstIP, "%d.%d.%d.%d", &dstip[0], &dstip[1], &dstip[2], &dstip[3]);
    printf("\nNetwork address inside function: %d.%d.%d.%d\n", dstip[0], dstip[1], dstip[2], dstip[3]);
    networkAddress[0] = dstip[0] & 0xff;
    networkAddress[1] = dstip[1] & 0xff;
    networkAddress[2] = dstip[2] & 0x000000fe;
    networkAddress[3] = 0;
}

void populateRoutingTable(){

    routingTable[string("10.1.0.0")].nextHopIP[3] = 0x01;
    routingTable[string("10.1.0.0")].nextHopIP[2] = 0x00;
    routingTable[string("10.1.0.0")].nextHopIP[1] = 0x63;
    routingTable[string("10.1.0.0")].nextHopIP[0] = 0x0a;
    
    routingTable[string("10.1.2.0")].nextHopIP[3] = 0x02;
    routingTable[string("10.1.2.0")].nextHopIP[2] = 0x00;
    routingTable[string("10.1.2.0")].nextHopIP[1] = 0x63;
    routingTable[string("10.1.2.0")].nextHopIP[0] = 0x0a;
}

void printRoutingTable(){    
    printf("Entries in Routing Table...\n");
    for(map<string, routerEntry>::iterator it = routingTable.begin();it!=routingTable.end(); it++){

        printf("Destination Network: %s\tNext Hop IP: ", (*it).first.c_str());
        for(int i=0;i<4;i++){
            printf("%d.", (*it).second.nextHopIP[i]);
        }
        printf("\n");
    }
}

void printIPPart(unsigned char *ip){

    printf("Packet is: \n");
    for(int i=0;i<100;i++){
        printf("%02x-",ip[i]);
    }
}
