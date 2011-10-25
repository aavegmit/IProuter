#include "sniffer.h"

using namespace std;

/*pushes the packet into parsing thread queue*/
void push_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet_orig){

    static int turn = 0;

    if(!macLookUpDone){
        struct sniff_ethernet *ethernet;
        struct ether_arp *arp_p;

        ethernet = (struct sniff_ethernet *)packet_orig;
        printf("In push_packet_inside\n");
        if(ethernet->ether_type == 1544){
            arp_p = (struct ether_arp *)(packet_orig + SIZE_ETHERNET);
            printf("In push_packet_inside_beforeUpdateMac\n");
            updateMacAddress( arp_p->arp_spa, arp_p->arp_sha);
        }
    }
    else{

        //printf("length of the captured packet is: %d\n", header->len);
        if(turn == NUM_PARSE_THREAD)
            turn = 0;
        packetInfo pi;
        pi.packet = (u_char *)malloc(header->len);
        memcpy(pi.packet, packet_orig, header->len);
        pi.len = header->len;
        //printf("Pushing the PACKET into list....\n");
        pthread_mutex_lock(&parsePacketLock[turn]);
        parsePacketList[turn].push_back(pi);
        pthread_cond_signal(&parsePacketCV[turn]);
        pthread_mutex_unlock(&parsePacketLock[turn]);
        turn++;
    }
}

void* snifferThread(void *args)
{

    // char *dev = (char *)args;			/* capture device name */
    snifferArgs *sf = (snifferArgs *)args;
    char *dev = sf->interface;
    char *filter_exp = sf->expression;		/* filter expression [3] */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */


    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
                dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 0, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* now we can set our callback function */
    pcap_loop(handle, NUM_PACKET_SNIFFED , push_packet, NULL);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");
    return 0;
}

