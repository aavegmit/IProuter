#include "arp.h"

void loadArpInfoInMemory(){
    bool tableComplete = false ;
    while(!tableComplete){
	tableComplete = true ;
	// Loop over the map here
	for(map<string, routerInfo>::iterator it = macLookUp.begin(); it != macLookUp.end(); ++it){
	    // find the mac for (*it).first 
	    if((*it).second.mac.empty()){
		(*it).second.mac = getArpFromKernel(const_cast<char *>((*it).first.c_str()), const_cast<char *>((*it).second.interface.c_str()) ) ;
		// if kernel does not have the arp value then send a dummy packet 
		if((*it).second.mac.empty()){
		    printf("Sending a packet to %s\n", (*it).first.c_str()) ;
		    tableComplete = false ;
		}
	    }
	}
	sleep(1) ;
    }
}


char *mac_ntoa(unsigned char *ptr){
    static char address[30];
    sprintf(address, "%02X:%02X:%02X:%02X:%02X:%02X",
	    ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
    return(address);
}

string getArpFromKernel(char *host, char* interface){
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
	    return("");
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
	return "";
    }
    close(s); /* Close the socket, we don't need it anymore. */

    printf("%s (%s) at ", host, inet_ntoa(sin->sin_addr));

    if(req.arp_flags & ATF_COM){
	printf("%s\n", mac_ntoa((unsigned char *)req.arp_ha.sa_data));
	return (string(mac_ntoa((unsigned char *)req.arp_ha.sa_data)));
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

    return "";
}

