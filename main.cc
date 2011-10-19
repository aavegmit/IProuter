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
//    router1.interface = "eth0" ;
//    router1.mac = "" ;
//    macLookUp[string("10.99.0.2")] = router1 ;
//
//    router1.interface = "eth0" ;
//    router1.mac = "" ;
//    macLookUp[string("10.99.0.1")] = router1 ;



    router1.interface = "eth1" ;
    router1.mac = "" ;
    macLookUp[string("192.168.0.14")] = router1 ;

    router1.interface = "eth1" ;
    router1.mac = "" ;
    macLookUp[string("192.168.0.10")] = router1 ;

    router1.interface = "eth1" ;
    router1.mac = "" ;
    macLookUp[string("192.168.0.16")] = router1 ;

    router1.interface = "eth1" ;
    router1.mac = "" ;
    macLookUp[string("192.168.0.21")] = router1 ;
    ///////////////////////////////////////////////////////


    printf("Looking up its own IP address and MAC address..\n") ;
    populateSelfMac() ;


    printf("Updating ARP cache..\n") ;
    loadArpInfoInMemory() ;
    printf("ARP table loaded into memory\n") ;

    // Wait for the Sniffer thread to close
    pthread_join(sniffer_t, NULL);	

    for(long i=0;i<NUM_PARSE_THREAD;i++){
        pthread_join(parsePacket_t[i], NULL);
    }

    printf("Main thread exiting...\n");
}

