#include "parse_packet.h"
#include "arp.h"

using namespace std;

pthread_mutex_t parsePacketLock[NUM_PARSE_THREAD];
pthread_cond_t parsePacketCV[NUM_PARSE_THREAD];
list<u_char* > parsePacketList[NUM_PARSE_THREAD];


void init_lockCV(){

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
        //        parsePacketList[i].clear();
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
    /*
     *  OK, this packet is TCP.
     */

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
{       //

    unsigned long sum;

    for(sum=0; nwords>0; nwords--)

        sum += *buf++;

    sum = (sum >> 16) + (sum &0xffff);

    sum += (sum >> 16);

    return (u_short)(~sum);

}
void modifyPacket(unsigned char *packet){


    /* declare pointers to packet headers */
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    struct sniff_ip *ip;              /* The IP header */
    struct ether_arp *arp_p;
    unsigned char networkAddress[4];
    unsigned char networkAdd[16];
    memset(networkAddress, '\0',4);

    int size_ip;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    printf("Hardware address of dst is: ");
    for(int i=0;i<ETHER_ADDR_LEN;i++){
        printf("%02x:", ethernet->ether_dhost[i]);
    }
    printf("\n\n");

    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
    }

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    getNetworkAddress((unsigned char *)(inet_ntoa(ip->ip_dst)), networkAddress);
    printf("Network address obtained is : %d.%d.%d.%d\n", networkAddress[0], networkAddress[1], networkAddress[2], networkAddress[3]);
    sprintf((char *)networkAdd,"%d.%d.%d.%d", networkAddress[0], networkAddress[1], networkAddress[2], networkAddress[3]);

    routerEntry rt;
    if(routingTable.find(string((char *)networkAdd)) != routingTable.end())
        rt = routingTable[string((char *)networkAdd)] ;
    else{
        printf("No entry in routing table...\n");
        //return;
    }

/*    routerInfo ri = macLookUp[string((char *)rt.nextHopIP)];

    printRouterInfo(ri);
*/
    /*******************************************************************************/

    //   need to modify packet now change mac address n all

    // chaning the dst and src MAC address
    /*for(int i=0;i<ETHER_ADDR_LEN;i++){
        ethernet->ether_shost[i] = ri.self_mac[i];
        ethernet->ether_dhost[i] = ri.mac[i];
    }
    // decrementing TTL value by 1
    ip->ip_ttl = (int)ip->ip_ttl - 1;*/
    if(ip->ip_ttl == 0){
        printf("TTL gone to 0....droping the packet....\n");
        return;
    }
    else{
        printf("BEFORE.....IP CHECK SUM IS: %d\n", ip->ip_sum);
        ip->ip_sum = 0;
        ip->ip_sum = csum((u_short *)ip, sizeof(ip));
        printf("AFTER.....IP CHECK SUM IS: %d\n", ip->ip_sum);
    }

   /******************************************************************************/

    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            //printTCP(packet, ip->ip_len, size_ip);
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            //return;
            break;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            //            return;
            break;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            //return;
            break;
        default:
            printf("   Protocol: unknown\n");
            //return;
            break;
    }
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
        cout << "IN PARSE_PACKET: "<< endl << parsePacketList[myID].front() << endl;
        //u_char *packet = (u_char *)((parsePacketList[myID].front()).c_str());
        u_char *packet = (u_char *)malloc(SNAP_LEN);
        memcpy(packet, parsePacketList[myID].front(), SNAP_LEN);
        parsePacketList[myID].pop_front();
        pthread_mutex_unlock(&parsePacketLock[myID]);
        //    static int count = 1;                   /* packet counter */
        //printIPPart((packet+14));
        modifyPacket(packet);

        free(packet);

    }// end of while

}

