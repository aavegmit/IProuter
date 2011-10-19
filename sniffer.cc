/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
* OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
* TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
* PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
    * REPAIR OR CORRECTION.
    * 
    * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
    * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
    * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
    * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
    * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
            * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
            * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
            * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
    * POSSIBILITY OF SUCH DAMAGES.
    * <end of "sniffex.c" terms>
    * 
    ****************************************************************************
    *
    * Below is an excerpt from an email from Guy Harris on the tcpdump-workers
    * mail list when someone asked, "How do I get the length of the TCP
    * payload?" Guy Harris' slightly snipped response (edited by him to
    * speak of the IPv4 header length and TCP data offset without referring
    * to bitfield structure members) is reproduced below:
    * 
    * The Ethernet size is always 14 bytes.
    * 
    * <snip>...</snip>
    *
    * In fact, you *MUST* assume the Ethernet header is 14 bytes, *and*, if 
    * you're using structures, you must use structures where the members 
    * always have the same size on all platforms, because the sizes of the 
    * fields in Ethernet - and IP, and TCP, and... - headers are defined by 
    * the protocol specification, not by the way a particular platform's C 
    * compiler works.)
    *
    * The IP header size, in bytes, is the value of the IP header length,
    * as extracted from the "ip_vhl" field of "struct sniff_ip" with
    * the "IP_HL()" macro, times 4 ("times 4" because it's in units of
            * 4-byte words).  If that value is less than 20 - i.e., if the value
    * extracted with "IP_HL()" is less than 5 - you have a malformed
    * IP datagram.
    *
    * The TCP header size, in bytes, is the value of the TCP data offset,
    * as extracted from the "th_offx2" field of "struct sniff_tcp" with
    * the "TH_OFF()" macro, times 4 (for the same reason - 4-byte words).
    * If that value is less than 20 - i.e., if the value extracted with
    * "TH_OFF()" is less than 5 - you have a malformed TCP segment.
    *
    * So, to find the IP header in an Ethernet packet, look 14 bytes after 
    * the beginning of the packet data.  To find the TCP header, look 
    * "IP_HL(ip)*4" bytes after the beginning of the IP header.  To find the
    * TCP payload, look "TH_OFF(tcp)*4" bytes after the beginning of the TCP
    * header.
    * 
    * To find out how much payload there is:
    *
    * Take the IP *total* length field - "ip_len" in "struct sniff_ip" 
    * - and, first, check whether it's less than "IP_HL(ip)*4" (after
            * you've checked whether "IP_HL(ip)" is >= 5).  If it is, you have
    * a malformed IP datagram.
    *
    * Otherwise, subtract "IP_HL(ip)*4" from it; that gives you the length
    * of the TCP segment, including the TCP header.  If that's less than
    * "TH_OFF(tcp)*4" (after you've checked whether "TH_OFF(tcp)" is >= 5),
    * you have a malformed TCP segment.
    *
    * Otherwise, subtract "TH_OFF(tcp)*4" from it; that gives you the
    * length of the TCP payload.
    *
    * Note that you also need to make sure that you don't go past the end 
    * of the captured data in the packet - you might, for example, have a 
    * 15-byte Ethernet packet that claims to contain an IP datagram, but if 
    * it's 15 bytes, it has only one byte of Ethernet payload, which is too 
    * small for an IP header.  The length of the captured data is given in 
    * the "caplen" field in the "struct pcap_pkthdr"; it might be less than 
    * the length of the packet, if you're capturing with a snapshot length 
    * other than a value >= the maximum packet size.
    * <end of response>
    * 
    ****************************************************************************
    * 
    * Example compiler command-line for GCC:
    *   gcc -Wall -o sniffex sniffex.c -lpcap
    * 
    ****************************************************************************
    *
    * Code Comments
    *
    * This section contains additional information and explanations regarding
    * comments in the source code. It serves as documentaion and rationale
    * for why the code is written as it is without hindering readability, as it
    * might if it were placed along with the actual code inline. References in
    * the code appear as footnote notation (e.g. [1]).
    *
    * 1. Ethernet headers are always exactly 14 bytes, so we define this
    * explicitly with "#define". Since some compilers might pad structures to a
    * multiple of 4 bytes - some versions of GCC for ARM may do this -
    * "sizeof (struct sniff_ethernet)" isn't used.
    * 
    * 2. Check the link-layer type of the device that's being opened to make
    * sure it's Ethernet, since that's all we handle in this example. Other
    * link-layer types may have different length headers (see [1]).
    *
    * 3. This is the filter expression that tells libpcap which packets we're
    * interested in (i.e. which packets to capture). Since this source example
    * focuses on IP and TCP, we use the expression "ip", so we know we'll only
    * encounter IP packets. The capture filter syntax, along with some
    * examples, is documented in the tcpdump man page under "expression."
    * Below are a few simple examples:
    *
    * Expression			Description
    * ----------			-----------
    * ip					Capture all IP packets.
    * tcp					Capture only TCP packets.
    * tcp port 80			Capture only TCP packets with a port equal to 80.
    * ip host 10.1.2.3		Capture all IP packets to or from host 10.1.2.3.
    *
    ****************************************************************************
    *
    */

#include "sniffer.h"

using namespace std;

/*pushes the packet into parsing thread queue*/
void push_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    static int turn = 0;

    if(turn == NUM_PARSE_THREAD)
        turn = 0;

    printf("Pushing the PACKET into list....\n");
    pthread_mutex_lock(&parsePacketLock[turn]);
    parsePacketList[turn].push_back((u_char *)packet);
    pthread_cond_signal(&parsePacketCV[turn]);
    pthread_mutex_unlock(&parsePacketLock[turn]);
    turn++;
}

void* snifferThread(void *args)
{

    char *dev = (char *)args;			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */

    char filter_exp[] = "ip and !(broadcast || multicast || dst host 10.10.0.1 || src host 10.99.0.3 || src host 10.10.0.2)";		/* filter expression [3] */
//    char filter_exp[] = "src host 192.168.0.19";		/* filter expression [3] */
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */


    /* find a capture device if not specified on command-line */
/*
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
        exit(EXIT_FAILURE);
    }
*/    

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
    handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
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

