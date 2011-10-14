#include "sniffer.h"
#include "config.h"
#include "arp.h"
#include "routingTable.h"
#include <sys/time.h>
#include <pthread.h>

map<string, routerInfo> macLookUp ;

int main(int argc, char **argv){

    char rv[] = INTERFACE_1;
    init_lockCV();

    pthread_t parsePacket_t[NUM_PARSE_THREAD];
    int temp[NUM_PARSE_THREAD];
    for(long i=0;i<NUM_PARSE_THREAD;i++){
        temp[i] = i;
        pthread_create(&parsePacket_t[i], NULL, parsePacketThread, (void *)temp[i]);
    }

    printf("Populating the routing table manually..\n") ;
    // Populate the table here
    
    
    
    // Populate the macLookUp also
    routerInfo router1 ;
    router1.interface = "eth1" ;
    router1.mac = "" ;
    macLookUp[string("192.168.0.14")] = router1 ;

    router1.interface = "eth1" ;
    router1.mac = "" ;
    macLookUp[string("192.168.0.17")] = router1 ;

    router1.interface = "eth1" ;
    router1.mac = "" ;
    macLookUp[string("192.168.0.19")] = router1 ;
    ///////////////////////////////////////////////////////





    printf("Updating ARP cache..\n") ;
    // Call the function here which loops over all the ip
    // addresses and finds their MAC address
    loadArpInfoInMemory() ;
    printf("ARP table loaded into memory\n") ;

    // Wait for the Sniffer thread to close
    pthread_join(sniffer_t, NULL);	

    for(long i=0;i<NUM_PARSE_THREAD;i++){
        pthread_join(parsePacket_t[i], NULL);
    }

    printf("Main thread exiting...\n");
}

