#include "sniffer.h"
#include "config.h"
#include "arp.h"
#include "routingTable.h"
#include "writePacket.h"
#include <sys/time.h>
#include <pthread.h>

map<string, routerInfo> macLookUp ;

int main(int argc, char **argv){


    printf("Populating the routing table manually..\n") ;

    pthread_t sniffer_t;

    // Populate the table here


    // Populate the macLookUp also
    routerInfo router1 ;
    router1.interface = "eth2" ;
    memset(router1.mac, 0x00, 6) ;
    macLookUp[string("10.99.0.2")] = router1 ;

    /*router1.interface = "eth2" ;
    memset(router1.mac, 0x00, 6) ;
    macLookUp[string("10.99.0.1")] = router1 ;*/

    /*router1.interface = "eth0" ;
      memset(router1.mac, 0x00, 6) ;
      macLookUp[string("192.168.0.13")] = router1 ;*/

/*        router1.interface = "eth0" ;
          memset(router1.mac, 0x00, 6) ;
          macLookUp[string("192.168.1.2")] = router1 ;*/
     
    ///////////////////////////////////////////////////////


    printf("Looking up its own IP address and MAC address..\n") ;
    populateSelfMac() ;
    populateRoutingTable();
    //printRoutingTable();

    struct snifferArgs sf;
    strcpy(sf.interface,macLookUp[string("10.99.0.2")].interface.c_str());
    strcpy(sf.expression, "arp and ether dst host 00:15:17:1e:03:46");
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
    //SNIFFER THREAD 1
    snifferArgs sf1;
    strcpy(sf1.interface,INTERFACE_1);
    //strcpy(sf1.expression, "ip and !(broadcast || multicast || dst host 10.99.0.1 || dst host 10.99.0.2 || dst host 10.10.0.1 || (src host 10.99.0.2 and dst host 10.99.0.3) || (src host 10.99.0.1 and dst host 10.99.0.3) || (src host 10.10.0.1 and dst host 10.10.0.2))");
    sprintf(sf1.expression, "ip and !(dst host 192.168.252.1 || broadcast || multicast || (src host 10.99.0.2 and dst host 10.99.0.3) || (src host 10.99.0.1 and dst host 10.99.0.3) || (src host 10.10.0.1 and dst host 10.10.0.2) || ether src %02x:%02x:%02x:%02x:%02x:%02x)", macLookUp[string("10.99.0.2")].self_mac[0], macLookUp[string("10.99.0.2")].self_mac[1], macLookUp[string("10.99.0.2")].self_mac[2], macLookUp[string("10.99.0.2")].self_mac[3], macLookUp[string("10.99.0.2")].self_mac[4], macLookUp[string("10.99.0.2")].self_mac[5]);

    //    strcpy(sf1.expression, "ip and src host 192.168.0.20 and dst host 192.168.0.13");
    pthread_create(&sniffer_t, NULL, snifferThread, (void *)&sf1);

    sleep(1);
    //SNIFFER THREAD 2
    pthread_t sniffer_t1;
    snifferArgs sf2;
    strcpy(sf2.interface,INTERFACE_2);
    //strcpy(sf2.expression, "ip and !(broadcast || multicast || src host 10.99.0.3 || src host 10.10.0.2 || dst host 10.99.0.1 || dst host 10.99.0.2 || dst host 10.10.0.1 || (src host 10.99.0.2 and dst host 10.99.0.3) || (src host 10.99.0.1 and dst host 10.99.0.3) || (src host 10.10.0.1 and dst host 10.10.0.2))");
//    sprintf(sf2.expression, "%s", sf1.expression);
    sprintf(sf2.expression, "ip and !(dst host 192.168.252.1 || broadcast || multicast || dst host 10.10.0.1 || (src host 10.99.0.2 and dst host 10.99.0.3) || (src host 10.99.0.1 and dst host 10.99.0.3) || (src host 10.10.0.1 and dst host 10.10.0.2) || ether src %02x:%02x:%02x:%02x:%02x:%02x)", macLookUp[string("10.99.0.2")].self_mac[0], macLookUp[string("10.99.0.2")].self_mac[1], macLookUp[string("10.99.0.2")].self_mac[2], macLookUp[string("10.99.0.2")].self_mac[3], macLookUp[string("10.99.0.2")].self_mac[4], macLookUp[string("10.99.0.2")].self_mac[5]);
    pthread_create(&sniffer_t1, NULL, snifferThread, (void *)&sf2);

    // inject packet thread
    snifferArgs sf3;
    strcpy(sf3.interface,INTERFACE_1);
    memset(sf3.expression, '\0', sizeof(sf3.expression));
    pthread_t inject_thread;
    pthread_create(&inject_thread, NULL, injectPacket, (void *)&sf3);

    // Wait for the Sniffer thread to close

    pthread_join(sniffer_t, NULL);	
    pthread_join(sniffer_t1, NULL);
    pthread_join(inject_thread, NULL);	
    for(long i=0;i<NUM_PARSE_THREAD;i++){
        pthread_join(parsePacket_t[i], NULL);
    }

    printf("Main thread exiting...\n");
}
