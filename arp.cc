#include "arp.h"

bool macLookUpDone = false;

void loadArpInfoInMemory(){
    bool tableComplete = false ;
    uint8_t blank_mac[6] ;
    memset(blank_mac, 0x00, 6) ;
    while(!tableComplete){
	tableComplete = true ;
	// Loop over the map here
	for(map<string, routerInfo>::iterator it = macLookUp.begin(); it != macLookUp.end(); ++it){
	    // find the mac for (*it).first 
	    if( memcmp( (*it).second.mac, blank_mac, 6) == 0 ){
		getArpFromKernel(const_cast<char *>((*it).first.c_str()), const_cast<char *>((*it).second.interface.c_str()), (*it).second.mac) ;
		// if kernel does not have the arp value then send an ARP request
		if(memcmp( (*it).second.mac, blank_mac, 6) == 0 ){
		    printf("Sending a packet to %s\n", (*it).first.c_str()) ;
		    sendArpRequest(const_cast<char *>((*it).first.c_str()), const_cast<char *>((*it).second.interface.c_str())) ;
		    tableComplete = false ;
		}
	    }
	}
	sleep(1) ;
    }
    macLookUpDone = true ;
}

char *mac_ntoa(unsigned char *ptr){
    static char address[30];
    sprintf(address, "%02X:%02X:%02X:%02X:%02X:%02X",
	    ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
    return(address);
}

void updateMacAddress(uint8_t *ip, uint8_t *mac ){
    unsigned char ip_array[16] ;
    unsigned char mac_array[6] ;
    memset(ip_array, 0x00, 16) ;
    sprintf((char *)ip_array, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]) ;
    memcpy(macLookUp[string((char *)ip_array)].mac,  mac, 6) ;
    printf("Mac is %s\n", mac_ntoa((unsigned char *)mac)) ;
}

void getArpFromKernel(char *host, char* interface, uint8_t *mac){
    int s;

    struct arpreq req;
    struct hostent *hp;
    struct sockaddr_in *sin;

    bzero((caddr_t)&req, sizeof(req));

    sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET; /* Address Family: Internet */
    sin->sin_addr.s_addr = inet_addr(host);

    if(sin->sin_addr.s_addr ==-1){
	if(!(hp = gethostbyname(host))){
	    fprintf(stderr, "arp: %s ", host);
	    herror((char *)NULL);
	    return ;
	}
	bcopy((char *)hp->h_addr, (char *)&sin->sin_addr, sizeof(sin->sin_addr));
    }

    if((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
	perror("socket() failed.");
	exit(-1);
    } /* Socket is opened.*/

    strcpy(req.arp_dev, interface);

    if(ioctl(s, SIOCGARP, (caddr_t)&req) <0){
	if(errno == ENXIO){
	    printf("%s (%s) -- no entry.\n", host, inet_ntoa(sin->sin_addr));
	} else {
	    perror("SIOCGARP");
	}
	close(s); /* Close the socket, we don't need it anymore. */
	return ;
    }
    close(s); /* Close the socket, we don't need it anymore. */

    printf("%s (%s) at ", host, inet_ntoa(sin->sin_addr));

    if(req.arp_flags & ATF_COM){
	printf("%s\n", mac_ntoa((unsigned char *)req.arp_ha.sa_data));
	memcpy(mac, (uint8_t *)req.arp_ha.sa_data, 6 );
    } else {
	printf("incomplete\n");
    }

    if(req.arp_flags & ATF_PERM){
	printf("ATF_PERM");
    }
    if(req.arp_flags & ATF_PUBL){
	printf("ATF_PUBL");
    }
    if(req.arp_flags & ATF_USETRAILERS){
	printf("ATF_USETRAILERS");
    }

    return ;
}

int sendArpRequest(char *host, char *interface){

    struct in_addr src_in_addr,targ_in_addr;
    struct arp_packet pkt;
    struct sockaddr sa;
    int sock;

    sock=socket(AF_INET,SOCK_PACKET,htons(ETH_P_RARP));
    if(sock<0){
	perror("socket");
	return -1;
    }

    pkt.frame_type = htons(ARP_FRAME_TYPE);
    pkt.hw_type = htons(ETHER_HW_TYPE);
    pkt.prot_type = htons(IP_PROTO_TYPE);
    pkt.hw_addr_size = ETH_HW_ADDR_LEN;
    pkt.prot_addr_size = IP_ADDR_LEN;
    pkt.op=htons(0x01);

    memset(pkt.targ_hw_addr, 0xff, ETH_HW_ADDR_LEN) ; 
    memset(pkt.rcpt_hw_addr, 0xff, ETH_HW_ADDR_LEN) ; 
    memcpy(pkt.src_hw_addr, macLookUp[host].self_mac, ETH_HW_ADDR_LEN) ;
    memcpy(pkt.sndr_hw_addr, macLookUp[host].self_mac, ETH_HW_ADDR_LEN) ;

    get_ip_addr(&src_in_addr,const_cast<char *>(macLookUp[host].self_ip.c_str()));
    get_ip_addr(&targ_in_addr,host);

    memcpy(pkt.sndr_ip_addr,&src_in_addr,IP_ADDR_LEN);
    memcpy(pkt.rcpt_ip_addr,&targ_in_addr,IP_ADDR_LEN);

//    bzero(pkt.padding,18);

    strcpy(sa.sa_data,interface) ;
    if(sendto(sock,&pkt,sizeof(pkt),0,&sa,sizeof(sa)) < 0){
	perror("sendto");
	return -1 ;
    }
    return(0) ;
}

void die(char* str){
    fprintf(stderr,"%s\n",str);
    exit(1);
}

void get_ip_addr(struct in_addr* in_addr,char* str){

    struct hostent *hostp;

    in_addr->s_addr=inet_addr(str);
    if(in_addr->s_addr == -1){
	if( (hostp = gethostbyname(str)))
	    bcopy(hostp->h_addr,in_addr,hostp->h_length);
	else {
	    fprintf(stderr,"send_arp: unknown host %s\n",str);
	    exit(1);
	}
    }
}

void populateSelfMac(){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;

    for(map<string, routerInfo>::iterator it = macLookUp.begin(); it != macLookUp.end(); ++it){
	printf("%s:\t", (*it).second.interface.c_str()) ;

	strncpy(ifr.ifr_name, (*it).second.interface.c_str() , IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	(*it).second.self_ip = string(inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr)) ;
	printf("%s\t", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

	ioctl(fd, SIOCGIFHWADDR, &ifr);
	memcpy((*it).second.self_mac, ifr.ifr_hwaddr.sa_data,6) ;
	for( int s = 0; s < 6; s++ )
	{
	    printf("%.2x ", (unsigned char)ifr.ifr_hwaddr.sa_data[s]);
	}
	printf("\n") ;

    }
    close(fd) ;
}
