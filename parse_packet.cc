#include "parse_packet.h"
#include "arp.h"
#include "writePacket.h"

using namespace std;

pthread_mutex_t parsePacketLock[NUM_PARSE_THREAD];
pthread_cond_t parsePacketCV[NUM_PARSE_THREAD];
list<packetInfo > parsePacketList[NUM_PARSE_THREAD];


void init_lockCV(){

    pthread_mutex_init(&mutex,NULL);
    pthread_cond_init(&cv,NULL);

    int res = 0;
    for(int i=0;i<NUM_PARSE_THREAD;i++){

        res = pthread_mutex_init(&parsePacketLock[i], NULL);
        if (res != 0){
            fprintf(stderr, "Lock init failed\n") ;
        }

        res = pthread_cond_init(&parsePacketCV[i], NULL);
        if (res != 0){
            fprintf(stderr, "CV init failed\n") ;
        }
    }
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
    void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
    void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;            /* number of bytes per line */
    int line_len;
    int offset = 0;                 /* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }
    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    return;
}

void printTCP(unsigned char *packet, int ip_len, int size_ip){

    int size_tcp;
    int size_payload;
    const struct sniff_tcp *tcp;            /* The TCP header */
    u_char *payload;                    /* Packet payload */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    }

    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip_len) - (size_ip + size_tcp);

    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
}

void printRouterInfo(routerInfo ri){

    printf("Destination MAC is: ");
    for(int i=0;i<6;i++){
        printf("%02x ", ri.mac[i]);
    }
    printf("\n");
    printf("Interface on which packet needs to be written: %s\n", ri.interface.c_str());
    printf("Self Mac is : ");
    for(int i=0;i<6;i++){
        printf("%02x ", ri.self_mac[i]);
    }
    printf("My IP is: %s\n", ri.self_ip.c_str());
}

u_short csum(u_short *buf, int nwords)
{       
    register int sum = 0;
    u_short answer = 0;
    register u_short *w = buf;
    register int nleft = nwords;

    while(nleft > 1){
        sum += *w++;
        nleft -= 2;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

void modifyPacket(packetInfo pi){


    /* declare pointers to packet headers */
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */
    struct ether_arp *arp_p;
    unsigned char networkAddress[7];
    unsigned char networkAdd[16];
    unsigned char nextHopIP[6];
    packetInfo icmp_response ;

    int size_ip;
    bool sendIcmp = false ;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(pi.packet);

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(pi.packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
    }
    ip->ip_ttl = ((uint8_t)ip->ip_ttl) - 1;

    u_char ipproto = ip->ip_p ;
    if(ip->ip_ttl == 0){
	// Send an ICMP TIME_EXCEED_MESSAGE
	ip->ip_ttl = 1;
	icmp_response.len = SIZE_ETHERNET + 20 + 8 + size_ip + 8;
        printf("Sending ICMP TIME_EXCEEDED_MESSAGE\n") ;
        icmp_response.packet = (u_char *)malloc(icmp_response.len) ;

        get_icmp_time_exceeded_response(&pi, &icmp_response) ;

        ip = (struct sniff_ip*)(icmp_response.packet + SIZE_ETHERNET);
        ethernet = (struct sniff_ethernet*)(icmp_response.packet);
        size_ip = 20;
        free(pi.packet) ;
        sendIcmp = true ;
    }
    // Check if icmp request is destined for itself
    else if(ipproto == IPPROTO_ICMP && isMyIp(ip->ip_dst) ){
        // Send an ICMP REPLY
        struct icmphdr *icp;
        icp = (struct icmphdr *)(pi.packet + SIZE_ETHERNET + 20) ;
        switch(icp->icmp_type){
            case 8:
                printf("ICMP ECHO request received %d\n", pi.len) ;
                icmp_response.len = 20 + (pi.len - size_ip )  ;
                icmp_response.packet = (u_char *)malloc(icmp_response.len) ;

                get_icmp_echo_response(&pi, &icmp_response) ;

                ip = (struct sniff_ip*)(icmp_response.packet + SIZE_ETHERNET);
                ethernet = (struct sniff_ethernet*)(icmp_response.packet);
                break;
        }
        size_ip = 20;
        free(pi.packet) ;
        sendIcmp = true ;
    }
    else if(isInMyLocalNetwork(ip->ip_dst)){
	free(pi.packet) ;
	return;
    }


    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    getNetworkAddress((unsigned char *)(inet_ntoa(ip->ip_dst)), networkAddress);
    //    printf("Network address obtained is : %d%c%d%c%d%c%d\n", networkAddress[0], networkAddress[1], networkAddress[2], networkAddress[3], networkAddress[4], networkAddress[5], networkAddress[6]);
    //sprintf((char *)networkAdd,"%d.%d.%d.%d", networkAddress[0], networkAddress[1], networkAddress[2], networkAddress[3]);

    routerEntry rt;
    if(routingTable.find(string((char *)networkAdd)) != routingTable.end())
        rt = routingTable[string((char *)networkAdd)] ;
    else{
        printf("No entry in routing table...\n");
        if(!sendIcmp)
            free(pi.packet);
        return;
    }

    sprintf((char *)nextHopIP,"%d.%d.%d.%d", rt.nextHopIP[0], rt.nextHopIP[1], rt.nextHopIP[2], rt.nextHopIP[3]);
    routerInfo ri = macLookUp[string((char *)nextHopIP)];

    //    printRouterInfo(ri);

    for(int i=0;i<ETHER_ADDR_LEN;i++){
        ethernet->ether_shost[i] = ri.self_mac[i];
        ethernet->ether_dhost[i] = ri.mac[i];
    }
    ip->ip_sum = 0;
    ip->ip_sum = csum((u_short *)ip, size_ip);

    pthread_mutex_lock(&mutex);
    if(sendIcmp)
        sendQueue.push_back(icmp_response);
    else
        sendQueue.push_back(pi);
    pthread_cond_signal(&cv);
    pthread_mutex_unlock(&mutex);
}

/*
 * dissect/print packet
 */
void* parsePacketThread(void *args)
{
    long myID = ((long )args);

    printf("My ID is: %ld\n",myID);

    while(1){

        pthread_mutex_lock(&parsePacketLock[myID]);
        if(parsePacketList[myID].empty()){
            pthread_cond_wait(&parsePacketCV[myID], &parsePacketLock[myID]);
        }
        packetInfo pi = parsePacketList[myID].front();
        parsePacketList[myID].pop_front();
        pthread_mutex_unlock(&parsePacketLock[myID]);
        printf("Packet length in parser is : %d\n", pi.len);
        modifyPacket(pi);
    }// end of while
}

bool isMyIp(struct in_addr dst){
    if(string((char *)inet_ntoa(dst)) == "10.10.0.2")
        return true;
    for(map<string, routerInfo>::iterator it = macLookUp.begin(); it != macLookUp.end(); ++it){
        if( (*it).second.self_ip == string((char *)inet_ntoa(dst)) )
            return true;
    }
    return false ;
}

bool isInMyLocalNetwork(struct in_addr dst){
    char *p;
    p = (char *)&dst ;
#define	UC(b)	(((int)b)&0xff)
    if(UC(p[0]) == 10 && UC(p[1]) == 99 && UC(p[2]) == 0)
	return true ;
    if(UC(p[0]) == 10 && UC(p[1]) == 10 && UC(p[2]) == 0)
	return true ;
    return false;
}
