#include "sniffer.h"
#include "config.h"
#include "arp.h"
#include "routingTable.h"
#include <sys/time.h>
#include <pthread.h>

map<string, routerInfo> macLookUp ;

int main(int argc, char **argv){


    printf("Populating the routing table manually..\n") ;

    struct snifferArgs sf;
    strcpy(sf.interface,INTERFACE_1);
    strcpy(sf.expression, "arp and ether dst host 00:1f:3b:c3:2c:d9");

    pthread_t sniffer_t;	
    pthread_create(&sniffer_t, NULL, snifferThread, (void *)&sf);

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
//    populateSelfMac() ;


    printf("Updating ARP cache..\n") ;
//    loadArpInfoInMemory() ;
    printf("ARP table loaded into memory\n") ;


    init_lockCV();

    pthread_t parsePacket_t[NUM_PARSE_THREAD];
    int temp[NUM_PARSE_THREAD];
    for(long i=0;i<NUM_PARSE_THREAD;i++){
        temp[i] = i;
        pthread_create(&parsePacket_t[i], NULL, parsePacketThread, (void *)temp[i]);
    }


    //pthread_t sniffer_t;
    snifferArgs sf1;
    strcpy(sf1.interface,INTERFACE_1);
    strcpy(sf1.expression, "ip and !(broadcast || multicast || dst host 10.10.0.1 || src host 10.99.0.3 || src host 10.10.0.2)");

    pthread_create(&sniffer_t, NULL, snifferThread, (void *)&sf1);

    // Wait for the Sniffer thread to close
    pthread_join(sniffer_t, NULL);	

    for(long i=0;i<NUM_PARSE_THREAD;i++){
        pthread_join(parsePacket_t[i], NULL);
    }

    printf("Main thread exiting...\n");
}

