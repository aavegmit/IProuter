#include "icmp.h"

/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */
int in_cksum(u_short *addr, int len){
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

    while (nleft > 1)  {
	sum += *w++;
	nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
	*(u_char *)(&answer) = *(u_char *)w ;
	sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;				/* truncate to 16 bits */
    return(answer);
}

void get_icmp_time_exceeded_response(packetInfo *pi, packetInfo *res){
    struct sniff_ip *ip, *res_ip;
    struct icmphdr *icp;
    ip = (struct sniff_ip*)(pi->packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip)*4;
    struct in_addr temp ;
    // copy the ethernet part
    // copy the ip header
    memcpy(res->packet, pi->packet, SIZE_ETHERNET + 20) ;
    res_ip = (struct sniff_ip*)(res->packet + SIZE_ETHERNET);
    // set ttl
    res_ip->ip_ttl = 64;
    // set version and header length
    res_ip->ip_vhl = 0x45 ;
    // set total length
    res_ip->ip_len = htons(20 + size_ip + 8 + 8) ;
    // set protocol as icmp
    res_ip->ip_p = IPPROTO_ICMP ;
    // set checksum as zero
    res_ip->ip_sum = 0 ;
    // swap ip src and dest
    temp = res_ip->ip_src ;
    res_ip->ip_src = res_ip->ip_dst;
    res_ip->ip_dst = temp ;
    // create a icmp packet
    icp = (struct icmphdr *)(res->packet + SIZE_ETHERNET + 20) ;
    // set type
    icp->icmp_type = ICMP_TIME_EXCEEDED;
    // set code
    icp->icmp_code = 0;
    // set checksum as zero
    icp->icmp_cksum = 0;
    icp->icmp_seq = 0;
    icp->icmp_id = 0;	
    // copy the original header
    // copy the next 8 bytes
    if(pi->len >= SIZE_ETHERNET + size_ip + 8)
	memcpy(res->packet + SIZE_ETHERNET + 20 + 8, pi->packet+SIZE_ETHERNET, size_ip + 8) ;
    else
	memcpy(res->packet + SIZE_ETHERNET + 20 + 8, pi->packet+SIZE_ETHERNET, size_ip) ;
    icp->icmp_cksum = in_cksum((u_short *)icp, 8);
}

void get_icmp_echo_response(packetInfo *pi, packetInfo *res){
    struct sniff_ip *ip, *res_ip;
    struct icmphdr *icp, *ori_icp;
    ip = (struct sniff_ip*)(pi->packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip)*4;
    struct in_addr temp ;
    ori_icp = (struct icmphdr *)(pi->packet + SIZE_ETHERNET + 20) ;
    // copy the ethernet part
    // copy the ip header
    memcpy(res->packet, pi->packet, SIZE_ETHERNET + 20) ;
    res_ip = (struct sniff_ip*)(res->packet + SIZE_ETHERNET);
    // set ttl
    res_ip->ip_ttl = 255;
    // set version and header length
    res_ip->ip_vhl = 0x45 ;
    // set total length
    res_ip->ip_len = htons(res->len - SIZE_ETHERNET)  ;
    // set protocol as icmp
    res_ip->ip_p = IPPROTO_ICMP ;
    // set checksum as zero
    res_ip->ip_sum = 0 ;
    // swap ip src and dest
    temp = res_ip->ip_src ;
    res_ip->ip_src = res_ip->ip_dst;
    res_ip->ip_dst = temp ;
    // create a icmp packet
    icp = (struct icmphdr *)(res->packet + SIZE_ETHERNET + 20) ;
    // set type
    icp->icmp_type = 0x00;
    // set code
    icp->icmp_code = 0;
    // set checksum as zero
    icp->icmp_cksum = 0;
    icp->icmp_seq = ori_icp->icmp_seq;
    icp->icmp_id = ori_icp->icmp_id  ;	
    // copy the data
    memcpy(res->packet + SIZE_ETHERNET + 20 + 8, pi->packet+SIZE_ETHERNET +28, res->len - 28 - SIZE_ETHERNET) ;
    icp->icmp_cksum = in_cksum((u_short *)icp, res->len - 20 - SIZE_ETHERNET);
}
