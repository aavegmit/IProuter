#include "writePacket.h"
using namespace std;

list<packetInfo > sendQueue;
pthread_mutex_t mutex;
pthread_cond_t cv;
void packet_injection(u_char*, uint32_t, u_char *, int );

void* injectPacket(void *s) 
{
    snifferArgs *sf = (snifferArgs *)s;
    u_char *user = (u_char *)sf->interface;
    packetInfo pi;
    int sock;
    int gwc = 0;

    sock=socket(AF_INET,SOCK_PACKET,htons(ETH_P_IP));
    if(sock<0){
	perror("socket");
    }
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
            packet_injection(user, pi.len, pi.packet, sock);
            free(pi.packet);
            printf("Write thread, queue size is: %d\n", sendQueue.size());
        }
        else
        {
            gwc++;
            printf("Write thread going on wait ....%d\n", gwc);
            pthread_mutex_lock(&mutex);
            pthread_cond_wait(&cv,&mutex);	
            pthread_mutex_unlock(&mutex);
            gwc++;
            printf("Write thread going on wait: %d, size is: %d\n", gwc, sendQueue.size());
        }

    }	// END OF THE WHILE LOOP OF THE WRITE THREAD

    pthread_exit(0);
}

void packet_injection (u_char* user, uint32_t len, u_char *packet, int sock)
{
    char* interface = (char *)user;
    struct sockaddr sa;


    strcpy(sa.sa_data,interface) ;
    if(sendto(sock,packet,len ,0,&sa,sizeof(sa)) < 0){
        perror("sendto");
        return ;
    }
    return ;


}
