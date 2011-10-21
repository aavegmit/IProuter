#include "icmp.h"


void icmp_send_time_exceeded(char *target){

    struct icmphdr *icp;
    register int cc;
    int i;
    // NOTE: figure out MAXPACKET
    u_char outpack[64];
    int sock;
    struct protoent *proto;
    int ident = getpid() & 0xFFFF;
    struct sockaddr whereto;
    struct sockaddr_in *to;
    struct hostent *hp;

    memset(&whereto, 0, sizeof(struct sockaddr));
    to = (struct sockaddr_in *)&whereto;
    to->sin_family = AF_INET;
    if (inet_aton(target, &to->sin_addr)) {
    }
    else {
	hp = gethostbyname(target);
	if (!hp) {
	    (void)fprintf(stderr,
		    "ping: unknown host %s\n", target);
	    exit(2);
	}
	to->sin_family = hp->h_addrtype;
	if (hp->h_length > (int)sizeof(to->sin_addr)) {
	    hp->h_length = sizeof(to->sin_addr);
	}
	memcpy(&to->sin_addr, hp->h_addr, hp->h_length);
    }

    if (!(proto = getprotobyname("icmp"))) {
	(void)fprintf(stderr, "ping: unknown protocol icmp.\n");
	exit(2);
    }
    if ((sock = socket(AF_INET, SOCK_RAW, proto->p_proto)) < 0) {
	if (errno==EPERM) {
	    fprintf(stderr, "ping: ping must run as root\n");
	}
	else perror("ping: socket");
	exit(2);
    }

    //    memset(outpack, 0x00, 64) ;
    icp = (struct icmphdr *)outpack;
    icp->icmp_type = ICMP_TIME_EXCEEDED;
    icp->icmp_code = 0;
    icp->icmp_cksum = 0;
    // NOTE: figure out sequence number
    icp->icmp_seq = 0;
    icp->icmp_id = ident;			/* ID */

    //    CLR(icp->icmp_seq % mx_dup_ck);

    cc = 64;			/* skips ICMP portion */

    /* compute ICMP checksum here */
    icp->icmp_cksum = in_cksum((u_short *)icp, cc);

    i = sendto(sock, (char *)outpack, cc, 0, &whereto,
	    sizeof(struct sockaddr));

    if (i < 0 || i != cc)  {
	if (i < 0)
	    perror("ping: sendto");
    }
}

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

void get_icmp_time_exceeded_response(packetInfo pi, packetInfo res){
    struct sniff_ip *ip, *res_ip;
    struct icmphdr *icp;
    ip = (struct sniff_ip*)(pi.packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip)*4;
    struct in_addr temp ;
    // copy the ethernet part
    // copy the ip header
    memcpy(res.packet, pi.packet, SIZE_ETHERNET + 20) ;
    res_ip = (struct sniff_ip*)(res.packet + SIZE_ETHERNET);
    // set ttl
    res_ip->ip_ttl = 255;
    // set version and header length
    res_ip->ip_vhl = 0x45 ;
    // set total length
    res_ip->ip_len = 20 + size_ip + 8 ;
    // set protocol as icmp
    res_ip->ip_p = IPPROTO_ICMP ;
    // set checksum as zero
    res_ip->ip_sum = 0 ;
    // swap ip src and dest
    temp = res_ip->ip_src ;
    res_ip->ip_src = res_ip->ip_dst;
    res_ip->ip_dst = temp ;
    // create a icmp packet
    icp = (struct icmphdr *)(res.packet + SIZE_ETHERNET + 20) ;
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
    memcpy(res.packet + SIZE_ETHERNET + 20 + 8, pi.packet+SIZE_ETHERNET, size_ip + 8) ;
    icp->icmp_cksum = in_cksum((u_short *)icp, 8+size_ip+8);
}
