#include "sniffer.h"
#include "config.h"
#include <sys/time.h>
#include <pthread.h>

int main(int argc, char **argv){

    char rv[] = INTERFACE_1;
    init_lockCV();

    pthread_t parsePacket_t[NUM_PARSE_THREAD];
    int temp[NUM_PARSE_THREAD];
    for(long i=0;i<NUM_PARSE_THREAD;i++){
        temp[i] = i;
        pthread_create(&parsePacket_t[i], NULL, parsePacketThread, (void *)temp[i]);
    }

    pthread_t sniffer_t;	
    pthread_create(&sniffer_t, NULL, snifferThread, rv);

    // Wait for the Sniffer thread to close
    pthread_join(sniffer_t, NULL);	

    for(long i=0;i<NUM_PARSE_THREAD;i++){
        pthread_join(parsePacket_t[i], NULL);
    }

    printf("Main thread exiting...\n");
}

