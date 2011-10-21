#include "sniffer.h"
#include "config.h"
#include "arp.h"
#include "routingTable.h"
#include <sys/time.h>
#include <pthread.h>

map<string, routerInfo> macLookUp ;

int main(int argc, char **argv){


    printf("Populating the routing table manually..\n") ;
    pthread_t sniffer_t;


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



    router1.interface = "eth0" ;
    memset(router1.mac, 0x00, 6) ;
    macLookUp[string("192.168.0.13")] = router1 ;

/*    router1.interface = "wlan0" ;
    memset(router1.mac, 0x00, 6) ;
    macLookUp[string("192.168.0.33")] = router1 ;
  */  
    ///////////////////////////////////////////////////////


    printf("Looking up its own IP address and MAC address..\n") ;
    populateSelfMac() ;
    populateRoutingTable();
    printRoutingTable();

    struct snifferArgs sf;
    strcpy(sf.interface,macLookUp[string("192.168.0.13")].interface.c_str());
    //sprintf(sf.expression, "arp and ether dst host %02x:%02x:%02x:%02x:%02x:%02x", (macLookUp[string("192.168.0.22")].self_mac)[0], (macLookUp[string("192.168.0.22")].self_mac)[1], (macLookUp[string("192.168.0.22")].self_mac)[2], (macLookUp[string("192.168.0.22")].self_mac)[3], (macLookUp[string("192.168.0.22")].self_mac)[4], (macLookUp[string("192.168.0.22")].self_mac)[5]);
    strcpy(sf.expression, "arp and ether dst host 00:21:9b:f8:ea:c6");
    pthread_create(&sniffer_t, NULL, snifferThread, (void *)&sf);
    
    printf("Updating ARP cache..\n") ;
    loadArpInfoInMemory() ;
    printf("ARP table loaded into memory\n") ;


/**********************************************************************************/
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
//    strcpy(sf1.expression, "ip and !(broadcast || multicast ||  dst net 10.99.0.0 || dst host 10.10.0.1 || src host 10.99.0.3 || src host 10.10.0.2 || (src host 10.10.0.1 and dst host 10.10.0.2))");
    strcpy(sf1.expression, "ip and src host 192.168.0.20 and dst host 192.168.0.24");

    pthread_create(&sniffer_t, NULL, snifferThread, (void *)&sf1);

    // Wait for the Sniffer thread to close
    pthread_join(sniffer_t, NULL);	

    for(long i=0;i<NUM_PARSE_THREAD;i++){
        pthread_join(parsePacket_t[i], NULL);
    }

    printf("Main thread exiting...\n");
}
