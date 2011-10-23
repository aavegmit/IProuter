#include "writePacket.h"
using namespace std;

list<packetInfo > sendQueue;
pthread_mutex_t mutex;
pthread_cond_t cv;
void packet_injection(u_char*, uint32_t, u_char * );

void* injectPacket(void *s) 
{
    snifferArgs *sf = (snifferArgs *)s;
    u_char *user = (u_char *)sf->interface;
    packetInfo pi;

    // WHILE LOOP OF THE INJECT THREAD
    while(1)
    {
        // INJECT-PACKET THREAD CHECKS IF THE QUEUE IS NOT EMPTY THEN IT TAKES OUT THE MESSAGE FROM QUEUE
        if(!sendQueue.empty())
        {
            pthread_mutex_lock(&mutex);
            pi = sendQueue.front();
            sendQueue.pop_front();
            pthread_mutex_unlock(&mutex);
            packet_injection(user, pi.len, pi.packet);
            free(pi.packet);

        }
        else
        {
            pthread_mutex_lock(&mutex);
            pthread_cond_wait(&cv,&mutex);	
            pthread_mutex_unlock(&mutex);
        }

    }	// END OF THE WHILE LOOP OF THE WRITE THREAD

    pthread_exit(0);
}

void packet_injection (u_char* user, uint32_t len, u_char *packet)
{
    char* inject_interface = (char *)user;
    char errbuf [ PCAP_ERRBUF_SIZE ];
    pcap_t* inject_int_desc;

    /* Setup the Injection Interface */
    if ( ( inject_int_desc = pcap_open_live ( inject_interface, BUFSIZ, 1, -1, errbuf ) ) == NULL )
    {
        printf ( "\nError: %s\n", errbuf );
        return;
    }

    double delay_time = 0;
    struct timespec tv;
    tv.tv_sec = ( time_t ) delay_time;
    tv.tv_nsec = ( long ) ( ( delay_time - tv.tv_sec ) * 1e+9 );
    nanosleep (&tv, &tv);

    pcap_inject ( inject_int_desc, packet, len );

    pcap_close ( inject_int_desc );
}
