#include "sniffer.h"
#include <sys/time.h>
#include <pthread.h>

int main(int argc, char **argv){

    char rv[] = "wlan0";

    pthread_t sniffer_t;	
    pthread_create(&sniffer_t, NULL, snifferThread, rv);

    // Wait for the Sniffer thread to close
    pthread_join(sniffer_t, NULL);	
}

